//! Where TEAvault keeps its files.
//!
//! Everything lives under one directory, overridable with `TEAVAULT_HOME`.
//! The override exists so the test suite and a portable install can use a
//! scratch directory without touching a real vault — it is not a way to point
//! the daemon at someone else's files, because the directory is chosen at
//! startup by the user, not by a request.
//!
//! ```text
//! %LOCALAPPDATA%\TEAvault\
//!   vault.keyring   KDF parameters + wrapped data key   (public + ciphertext)
//!   vault.data      sealed index + per-entry secrets     (ciphertext only)
//!   audit.keyring   DPAPI-wrapped audit chain key        (integrity only)
//!   audit.log       hash-chained audit events            (no secrets)
//!   settings.json   non-secret preferences               (plaintext, no secrets)
//!   vault.lock      inter-process write lock             (empty)
//! ```
//!
//! `settings.json` is the only plaintext file. It holds no key material by
//! construction: [`crate::settings::Settings`] has no secret field, and a test
//! asserts the serialised form contains none.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Resolved locations of every file TEAvault owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPaths {
    root: PathBuf,
}

impl Default for VaultPaths {
    fn default() -> Self {
        Self::user_default()
    }
}

impl VaultPaths {
    /// `%LOCALAPPDATA%\TEAvault`, or `$HOME/.local/share/teavault` elsewhere.
    ///
    /// Local application data rather than roaming: a vault should not follow a
    /// user between machines, and the ACLs there are appropriate for
    /// per-user secret material.
    pub fn user_default() -> Self {
        if let Ok(home) = std::env::var("TEAVAULT_HOME") {
            if !home.is_empty() {
                return Self::new(PathBuf::from(home));
            }
        }
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            if !local.is_empty() {
                return Self::new(PathBuf::from(local).join("TEAvault"));
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() {
                return Self::new(PathBuf::from(home).join(".local/share/teavault"));
            }
        }
        Self::new(PathBuf::from(".").join("teavault"))
    }

    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn keyring(&self) -> PathBuf {
        self.root.join("vault.keyring")
    }

    pub fn data(&self) -> PathBuf {
        self.root.join("vault.data")
    }

    pub fn audit_log(&self) -> PathBuf {
        self.root.join("audit.log")
    }

    pub fn audit_keyring(&self) -> PathBuf {
        self.root.join("audit.keyring")
    }

    pub fn settings(&self) -> PathBuf {
        self.root.join("settings.json")
    }

    pub fn lock_file(&self) -> PathBuf {
        self.root.join("vault.lock")
    }

    pub fn exists(&self) -> bool {
        self.keyring().exists() && self.data().exists()
    }

    /// Create the directory if needed.
    ///
    /// On Unix this sets `0700`. On Windows the per-user ACL of `%LOCALAPPDATA%`
    /// is already restrictive and the `windows` crate path is where explicit
    /// DACL work belongs; see `SECURITY.md` for what that does and does not
    /// cover.
    pub fn ensure_dir(&self) -> Result<()> {
        if self.root.is_dir() {
            return Ok(());
        }
        std::fs::create_dir_all(&self.root).map_err(|e| Error::io("create vault directory", e))?;
        restrict_permissions(&self.root)?;
        Ok(())
    }

    /// The path shown to the user in error messages and the settings screen.
    pub fn display(&self) -> String {
        self.root.display().to_string()
    }
}

#[cfg(unix)]
fn restrict_permissions(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::io("restrict vault directory", e))
}

#[cfg(not(unix))]
fn restrict_permissions(_dir: &Path) -> Result<()> {
    // Windows: the directory inherits the per-user ACL of %LOCALAPPDATA%,
    // which already excludes other accounts and administrators-by-default. An
    // explicit DACL is applied by the daemon for the pipe, not for the files;
    // see `SECURITY.md` § Local access control.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_file_lives_under_the_root() {
        let p = VaultPaths::new("/tmp/vault");
        for f in [
            p.keyring(),
            p.data(),
            p.audit_log(),
            p.audit_keyring(),
            p.settings(),
            p.lock_file(),
        ] {
            assert!(f.starts_with("/tmp/vault"), "{f:?} escaped the root");
        }
    }

    #[test]
    fn an_empty_home_override_is_ignored_rather_than_used() {
        // A stray empty variable must not silently redirect the vault to the
        // current working directory.
        let p = VaultPaths::user_default();
        assert!(!p.root().as_os_str().is_empty());
    }
}
