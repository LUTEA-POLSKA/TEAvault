//! Clipboard access, behind a trait.
//!
//! Core has `#![deny(unsafe_code)]` and no Win32 dependency, so the clipboard
//! is reached through this trait. The daemon supplies the Windows
//! implementation; tests supply a recording fake.
//!
//! ## The rule that matters
//!
//! **Only clear the clipboard if it still holds what we put there.** Anything
//! else would destroy whatever the user copied in the meantime — a password
//! manager that eats an unrelated copied password is worse than one that never
//! clears at all. [`Clipboard::clear_if_unchanged`] is therefore the only clear
//! operation offered; there is no unconditional `clear`.
//!
//! ## What clearing cannot do
//!
//! Clearing the clipboard does not un-copy a secret. Any program can already
//! have read it, the clipboard history feature in Windows may have recorded it,
//! and a screen-sharing tool may have captured it. The clipboard is a channel to
//! the whole user session, not to this process. The UI says so.

use crate::error::{Error, Result};

/// A clipboard TEAvault can write to and clear.
///
/// `Send + Sync` because the daemon's deadline thread clears while the pipe
/// thread may be writing.
pub trait Clipboard: Send + Sync {
    /// Replace the clipboard contents.
    fn set(&self, text: &str) -> Result<()>;

    /// Current contents, if readable.
    fn get(&self) -> Result<Option<String>>;

    /// Clear, but only if the contents still equal `expected`.
    ///
    /// Returns whether it cleared.
    fn clear_if_unchanged(&self, expected: &str) -> Result<bool>;
}

/// Refuses every clipboard operation.
///
/// The default. A vault with no clipboard can still be used for everything
/// except copying a key by hand, which fails loudly rather than silently
/// pretending to have copied something.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoClipboard;

impl Clipboard for NoClipboard {
    fn set(&self, _text: &str) -> Result<()> {
        Err(Error::io(
            "clipboard",
            std::io::Error::other("no clipboard backend is available"),
        ))
    }

    fn get(&self) -> Result<Option<String>> {
        Ok(None)
    }

    fn clear_if_unchanged(&self, _expected: &str) -> Result<bool> {
        Ok(false)
    }
}

/// An in-memory clipboard, for tests.
#[derive(Debug, Default)]
pub struct MemoryClipboard {
    inner: std::sync::Mutex<Option<String>>,
}

impl MemoryClipboard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Put something in *without* TEAvault's involvement, to simulate the user
    /// copying something else.
    pub fn externally_set(&self, text: &str) {
        *self.inner.lock().expect("poisoned") = Some(text.to_string());
    }
}

impl Clipboard for MemoryClipboard {
    fn set(&self, text: &str) -> Result<()> {
        *self.inner.lock().expect("poisoned") = Some(text.to_string());
        Ok(())
    }

    fn get(&self) -> Result<Option<String>> {
        Ok(self.inner.lock().expect("poisoned").clone())
    }

    fn clear_if_unchanged(&self, expected: &str) -> Result<bool> {
        let mut g = self.inner.lock().expect("poisoned");
        match &*g {
            Some(cur) if cur == expected => {
                *g = None;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clearing_only_happens_when_the_content_still_matches() {
        let c = MemoryClipboard::new();
        c.set("sk-secret").unwrap();
        assert!(c.clear_if_unchanged("sk-secret").unwrap());
        assert_eq!(c.get().unwrap(), None);
    }

    #[test]
    fn unrelated_clipboard_content_is_never_destroyed() {
        // The user copied a password from another manager while our key sat on
        // the clipboard. Wiping it would be a data-loss bug.
        let c = MemoryClipboard::new();
        c.set("sk-secret").unwrap();
        c.externally_set("some other password");

        assert!(!c.clear_if_unchanged("sk-secret").unwrap());
        assert_eq!(c.get().unwrap().as_deref(), Some("some other password"));
    }

    #[test]
    fn clearing_an_already_empty_clipboard_is_harmless() {
        let c = MemoryClipboard::new();
        assert!(!c.clear_if_unchanged("anything").unwrap());
    }

    #[test]
    fn the_default_backend_refuses_rather_than_silently_succeeding() {
        let c = NoClipboard;
        assert!(c.set("x").is_err());
        assert!(!c.clear_if_unchanged("x").unwrap());
    }
}
