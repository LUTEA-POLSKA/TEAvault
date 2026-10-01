//! Non-secret preferences.
//!
//! Everything here is safe to read, safe to write in the clear, and safe to
//! show on screen. The type has no field that could hold key material, and a
//! test asserts the serialised form stays that way — a setting file that
//! quietly accumulated a passphrase would be a very bad place to discover it.
//!
//! These are *preferences*. None of them can weaken the crypto: the KDF
//! parameters live in the keyring, and the passphrase policy is enforced in
//! [`crate::session`].

use serde::{Deserialize, Serialize};

use crate::{error::Result, model::now_rfc3339};

/// How long an unlocked vault stays open without activity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoLock {
    /// Never lock on a timer. The user can still lock manually, and locking
    /// still happens on sign-out and on quit.
    Never,
    /// Lock after this many seconds of inactivity. `0` is rejected as a value:
    /// it would look like "never" while behaving like "immediately", which is
    /// a good way to make a user think auto-lock is broken.
    AfterSeconds(u32),
}

impl Default for AutoLock {
    fn default() -> Self {
        Self::AfterSeconds(300)
    }
}

impl AutoLock {
    /// Effective timeout, or `None` for [`AutoLock::Never`].
    pub fn seconds(&self) -> Option<u64> {
        match self {
            Self::Never => None,
            Self::AfterSeconds(s) => Some(*s as u64),
        }
    }
}

/// Everything the user can change. No secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub auto_lock: AutoLock,
    /// How long a copied key stays on the clipboard. `0` disables clearing,
    /// which the UI presents as a deliberate choice with a warning.
    #[serde(default = "default_clipboard_secs")]
    pub clipboard_clear_seconds: u32,
    /// Start with Windows.
    #[serde(default)]
    pub autostart: bool,
    /// Close the main window hides it rather than quitting, so the background
    /// process — and the tray — stay available. On by default; the whole
    /// low-idle design depends on the daemon outliving the window.
    #[serde(default = "default_true")]
    pub close_window_hides: bool,
    /// Minimum acceptable master passphrase length, in characters.
    #[serde(default = "default_min_passphrase_len")]
    pub min_passphrase_chars: u32,
    /// Write a fresh encrypted backup after every N key changes. `0` disables.
    #[serde(default = "default_backup_every")]
    pub auto_backup_every_changes: u32,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
}

fn default_clipboard_secs() -> u32 {
    30
}
fn default_true() -> bool {
    true
}
fn default_min_passphrase_len() -> u32 {
    12
}
fn default_backup_every() -> u32 {
    10
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock: AutoLock::default(),
            clipboard_clear_seconds: default_clipboard_secs(),
            autostart: false,
            close_window_hides: true,
            min_passphrase_chars: default_min_passphrase_len(),
            auto_backup_every_changes: default_backup_every(),
            created_at: String::new(),
            updated_at: String::new(),
        }
    }
}

impl Settings {
    /// Reject values that would make the product behave in a way the user did
    /// not ask for and cannot easily see.
    pub fn validate(&self) -> Result<()> {
        use crate::error::Error;
        if let AutoLock::AfterSeconds(s) = self.auto_lock {
            if s == 0 {
                return Err(Error::invalid(
                    "auto_lock",
                    "0 seconds is not a setting; use \"never\" instead",
                ));
            }
            if s < 10 {
                return Err(Error::invalid(
                    "auto_lock",
                    "below 10 seconds the vault locks faster than a person can react",
                ));
            }
        }
        if self.min_passphrase_chars < 8 {
            return Err(Error::invalid(
                "min_passphrase_chars",
                "below 8 characters a passphrase is not a passphrase",
            ));
        }
        if self.clipboard_clear_seconds > 3600 {
            return Err(Error::invalid(
                "clipboard_clear_seconds",
                "an hour is already too long for a key on the clipboard",
            ));
        }
        Ok(())
    }

    /// Apply validated changes and stamp `updated_at`.
    pub fn apply(&mut self, next: Settings) -> Result<()> {
        next.validate()?;
        let created = if self.created_at.is_empty() {
            next.created_at.clone()
        } else {
            std::mem::take(&mut self.created_at)
        };
        self.auto_lock = next.auto_lock;
        self.clipboard_clear_seconds = next.clipboard_clear_seconds;
        self.autostart = next.autostart;
        self.close_window_hides = next.close_window_hides;
        self.min_passphrase_chars = next.min_passphrase_chars;
        self.auto_backup_every_changes = next.auto_backup_every_changes;
        self.created_at = if created.is_empty() {
            now_rfc3339()
        } else {
            created
        };
        self.updated_at = now_rfc3339();
        self.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        Settings::default().validate().unwrap();
    }

    #[test]
    fn settings_serialise_to_no_secret_shaped_field() {
        // Check the *keys*, not the serialised text: `min_passphrase_chars`
        // legitimately contains the substring "passphrase" while being a length
        // policy, not a passphrase.
        let value = serde_json::to_value(Settings::default()).unwrap();
        let obj = value.as_object().expect("settings serialise as an object");
        for forbidden in ["passphrase", "secret", "key_value", "dek", "token"] {
            assert!(
                !obj.contains_key(forbidden),
                "settings exposed a {forbidden} field"
            );
        }
        // And no value may look like key material either.
        let json = serde_json::to_string(&Settings::default()).unwrap();
        assert!(
            !json.contains("sk-"),
            "a key-shaped value leaked into settings"
        );
    }

    #[test]
    fn auto_lock_of_zero_seconds_is_rejected_rather_than_silently_meaning_never() {
        let s = Settings {
            auto_lock: AutoLock::AfterSeconds(0),
            ..Default::default()
        };
        assert!(s.validate().is_err());
    }

    #[test]
    fn an_absurdly_short_auto_lock_is_rejected() {
        let s = Settings {
            auto_lock: AutoLock::AfterSeconds(3),
            ..Default::default()
        };
        assert!(s.validate().is_err());
    }

    #[test]
    fn never_is_a_distinct_valid_choice() {
        let s = Settings {
            auto_lock: AutoLock::Never,
            ..Default::default()
        };
        s.validate().unwrap();
        assert_eq!(s.auto_lock.seconds(), None);
        assert_eq!(Settings::default().auto_lock.seconds(), Some(300));
    }

    #[test]
    fn a_passphrase_minimum_below_eight_is_rejected() {
        let s = Settings {
            min_passphrase_chars: 4,
            ..Default::default()
        };
        assert!(s.validate().is_err());
    }

    #[test]
    fn a_clipboard_timeout_over_an_hour_is_rejected() {
        let s = Settings {
            clipboard_clear_seconds: 7200,
            ..Default::default()
        };
        assert!(s.validate().is_err());
    }

    #[test]
    fn apply_keeps_created_at_and_moves_updated_at() {
        let mut s = Settings {
            created_at: "2026-01-01T00:00:00Z".into(),
            ..Default::default()
        };
        let before = s.created_at.clone();
        s.apply(Settings {
            autostart: true,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(s.created_at, before);
        assert_ne!(s.updated_at, "");
        assert!(s.autostart);
    }

    #[test]
    fn apply_rejects_an_invalid_change_and_changes_nothing() {
        let mut s = Settings::default();
        let original = s.clone();
        let bad = Settings {
            auto_lock: AutoLock::AfterSeconds(1),
            autostart: true,
            ..Default::default()
        };
        assert!(s.apply(bad).is_err());
        assert_eq!(
            s, original,
            "a rejected change must not be partially applied"
        );
    }
}
