//! Windows clipboard.
//!
//! `unsafe`, confined to this file so the core stays `#![deny(unsafe_code)]`.
//!
//! The one rule implemented here is the one that matters: **clear only if the
//! content is still ours.** A password manager that eats an unrelated copied
//! password is worse than one that never clears at all.

#![allow(dead_code)]

use std::ptr;

use teavault_core::{clipboard::Clipboard, error::Error, error::Result};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{HANDLE, HGLOBAL},
        System::{
            DataExchange::{
                CloseClipboard, GetClipboardData, OpenClipboard, RegisterClipboardFormatW,
                SetClipboardData,
            },
            Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE},
        },
    },
};

/// `CF_UNICODETEXT` is 13, per the Win32 headers. The registered format is
/// preferred when it differs, so query it once per call rather than trusting the
/// constant blindly.
const CF_UNICODETEXT_FALLBACK: u32 = 13;

fn io(context: &'static str, e: windows::core::Error) -> Error {
    Error::io(context, std::io::Error::other(e.to_string()))
}

/// Open the clipboard, run `f`, and always close it.
///
/// The clipboard is a single global resource: leaving it open on any path would
/// block every other application on the desktop.
fn with_clipboard<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    unsafe {
        OpenClipboard(None).map_err(|e| io("open the clipboard", e))?;
        struct Guard;
        impl Drop for Guard {
            fn drop(&mut self) {
                unsafe {
                    let _ = CloseClipboard();
                }
            }
        }
        let _guard = Guard;
        f()
    }
}

fn unicode_format() -> u32 {
    let name: Vec<u16> = "CF_UNICODETEXT"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let id = unsafe { RegisterClipboardFormatW(PCWSTR(name.as_ptr())) };
    if id == 0 {
        CF_UNICODETEXT_FALLBACK
    } else {
        id
    }
}

fn read_text() -> Result<Option<String>> {
    with_clipboard(|| unsafe { read_text_locked() })
}

/// Read clipboard text, inside one `OpenClipboard` window.
///
/// Bounds are taken from `GlobalSize`, not from scanning for a terminator. A
/// clipboard owner is another process: it may publish a non-`CF_UNICODETEXT`
/// blob, or a buffer with no NUL anywhere in it. Scanning for a terminator with a
/// raw pointer in that case walks straight off the end of the allocation — an
/// out-of-bounds read inside the one process holding the data key — and allocates
/// without limit for whatever it finds first.
unsafe fn read_text_locked() -> Result<Option<String>> {
    let handle =
        unsafe { GetClipboardData(unicode_format()) }.map_err(|e| io("read the clipboard", e))?;
    if handle.is_invalid() {
        // Nothing of that format on the clipboard: not ours.
        return Ok(None);
    }

    unsafe {
        let bytes = windows::Win32::System::Memory::GlobalSize(HGLOBAL(handle.0));
        // A CF_UNICODETEXT block is UTF-16 with a double NUL, so anything this
        // large is not text. Refusing beats trusting the size of a foreign buffer.
        if !(2..=MAX_CLIPBOARD_BYTES).contains(&bytes) {
            return Ok(None);
        }

        let p = GlobalLock(HGLOBAL(handle.0));
        if p.is_null() {
            return Ok(None);
        }

        let units = (bytes as usize) / std::mem::size_of::<u16>();
        let slice = std::slice::from_raw_parts(p as *const u16, units);
        // Cut at the first terminator *within* the block, so a missing one cannot
        // extend the read past the allocation.
        let len = slice.iter().position(|&c| c == 0).unwrap_or(units);

        let mut out = String::from_utf16_lossy(&slice[..len]);
        let _ = GlobalUnlock(HGLOBAL(handle.0));

        // Clipboard contents are someone else's data. Truncate rather than hand a
        // multi-megabyte string to a comparison.
        if out.len() > MAX_CLIPBOARD_CHARS {
            out.truncate(MAX_CLIPBOARD_CHARS);
        }
        Ok(Some(out))
    }
}
/// Largest clipboard block accepted, in bytes.
///
/// An API key is a few hundred bytes. Anything past this is not something TEAvault
/// put there, and refusing it bounds the work an unrelated process can cause in
/// the daemon.
const MAX_CLIPBOARD_BYTES: usize = 1024 * 1024;

/// Largest clipboard string compared against a copied secret.
const MAX_CLIPBOARD_CHARS: usize = 64 * 1024;

fn write_text(text: &str) -> Result<()> {
    with_clipboard(|| {
        unsafe {
            // CF_UNICODETEXT requires a double NUL terminator.
            let mut wide: Vec<u16> = text.encode_utf16().collect();
            wide.push(0);
            wide.push(0);

            let bytes = std::mem::size_of_val(&wide[..]);
            let hg = GlobalAlloc(GMEM_MOVEABLE, bytes).map_err(|_| {
                Error::io(
                    "clipboard",
                    std::io::Error::other("could not allocate clipboard memory"),
                )
            })?;

            let p = GlobalLock(HGLOBAL(hg.0));
            if p.is_null() {
                let _ = windows::Win32::Foundation::GlobalFree(Some(HGLOBAL(hg.0)));
                return Err(Error::io(
                    "clipboard",
                    std::io::Error::other("could not lock clipboard memory"),
                ));
            }
            ptr::copy_nonoverlapping(wide.as_ptr(), p as *mut u16, wide.len());
            let _ = GlobalUnlock(HGLOBAL(hg.0));

            // Ownership transfers to the clipboard on success; on failure we
            // still own it and must free it.
            if SetClipboardData(unicode_format(), Some(HANDLE(hg.0))).is_err() {
                let _ = windows::Win32::Foundation::GlobalFree(Some(HGLOBAL(hg.0)));
                return Err(Error::io("clipboard", std::io::Error::last_os_error()));
            }
            Ok(())
        }
    })
}

fn clear_locked() -> Result<()> {
    unsafe {
        // Passing `None` *removes* the format from the clipboard — the documented
        // behaviour for a NULL handle. That is what we want: the clipboard itself
        // belongs to the explorer, not to us, and leaving an empty format behind
        // would be a different and stranger outcome than removing ours.
        SetClipboardData(unicode_format(), None)
            .map_err(|_| Error::io("clipboard", std::io::Error::last_os_error()))?;
        Ok(())
    }
}

/// The real clipboard.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsClipboard;

impl Clipboard for WindowsClipboard {
    fn set(&self, text: &str) -> Result<()> {
        write_text(text)
    }

    fn get(&self) -> Result<Option<String>> {
        read_text()
    }

    /// Clear, but only if the clipboard still holds `expected`.
    ///
    /// ## The compare and the clear happen under one lock
    ///
    /// This used to be `read_text()? == expected` followed by a separate
    /// `clear()` — two `OpenClipboard` windows. Between them any other process
    /// could replace the contents, so TEAvault would compare its own secret,
    /// decide "still ours", and then wipe whatever the user had copied in the
    /// meantime.
    ///
    /// That is precisely the failure the whole conditional-clear design exists to
    /// prevent: a password manager that eats an unrelated copied password is
    /// worse than one that never clears at all. `OpenClipboard` fails while
    /// another process holds it, which is the retry signal — Win32 gives no other
    /// way to hold a critical section across two operations.
    fn clear_if_unchanged(&self, expected: &str) -> Result<bool> {
        for _ in 0..CLIPBOARD_RETRIES {
            match with_clipboard(|| {
                let current = unsafe { read_text_locked() }?;
                match current {
                    Some(current) if current == expected => {
                        clear_locked()?;
                        Ok(true)
                    }
                    // Something else is there, or nothing is. Either way, not ours.
                    _ => Ok(false),
                }
            }) {
                Ok(outcome) => return Ok(outcome),
                Err(_) if is_busy() => {
                    // Another process owns the clipboard. Yield and try again
                    // rather than concluding the value is not ours.
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(e) => return Err(e),
            }
        }
        // Still contended after every attempt. Report "not ours" and leave the
        // clipboard alone: failing to clear is recoverable, destroying the user's
        // clipboard is not.
        Ok(false)
    }
}

/// How many times to retry when another process owns the clipboard.
const CLIPBOARD_RETRIES: usize = 20;

/// Whether the last clipboard error was contention rather than a real failure.
fn is_busy() -> bool {
    matches!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(5) // ERROR_ACCESS_DENIED, what OpenClipboard returns while held
    )
}
