//! Unlock, lock, and failed-attempt limiting.
//!
//! ## What a session holds
//!
//! The data key, and nothing else. No passphrase, ever — it is used to derive
//! the KEK inside [`Keyring::unwrap_dek`] and then dropped. The session's job
//! is to hold the smallest possible amount of the smallest possible amount of
//! key material for the shortest possible time.
//!
//! ## What a restart does
//!
//! Locks it. There is no path that leaves the vault unlocked across a process
//! restart, and no DPAPI-wrapped copy of the data key, because such a copy
//! would hand the key to every process running as the user and destroy the
//! passphrase barrier. This is the reason DPAPI is used *only* for the audit
//! chain key — see [`crate::audit::AuditKeyRing`].
//!
//! ## There is no auto-lock
//!
//! An earlier design locked the vault after an idle timeout. It is gone, and
//! deliberately so: a timer cannot be reconciled with the rule that an idle
//! vault costs nothing, because honouring it means either a background thread
//! that wakes up to check or a window in which the key outlives the timeout.
//! Both are worse than not having the feature. Locking is therefore explicit —
//! [`Session::lock`] — and a restart is the backstop. Nothing here reads a
//! clock to decide whether to lock, so there is no idle path left to audit.

use std::time::{Duration, Instant};

use crate::{
    crypto::keyring::Keyring,
    crypto::secret::SecretBytes,
    error::{DenyReason, Error, Result},
};

/// Consecutive wrong-passphrase attempts before the vault refuses to even try.
pub const MAX_FAILED_ATTEMPTS: u32 = 5;

/// How long the vault stays unusable after the attempt limit is hit.
///
/// Not a strong defence — an attacker who has the keyring file and no time
/// limit will get through eventually — but it turns an unlimited online search
/// into a slow one and makes a scripted attempt fail visibly rather than
/// silently.
pub const LOCKOUT: Duration = Duration::from_secs(60);

/// An unlocked vault.
pub struct Session {
    /// `None` while locked.
    dek: Option<SecretBytes>,
    /// When the session was opened.
    opened_at: Option<Instant>,
    /// When the last failed attempt happened, for lockout.
    failed_attempts: u32,
    locked_out_until: Option<Instant>,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    /// A locked session. The state every process starts in.
    pub fn new() -> Self {
        Self {
            dek: None,
            opened_at: None,
            failed_attempts: 0,
            locked_out_until: None,
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.dek.is_some()
    }

    /// Seconds the vault has been unlocked, or `None` while locked.
    pub fn unlocked_for(&self) -> Option<Duration> {
        self.opened_at.map(|t| t.elapsed())
    }

    /// Borrow the data key, or refuse.
    ///
    /// Every secret operation goes through here, so "locked means no secrets"
    /// is enforced in one place rather than at each call site.
    pub fn require_dek(&self) -> Result<&SecretBytes> {
        self.dek.as_ref().ok_or(Error::Locked)
    }

    /// Attempt to unlock.
    ///
    /// `keyring` is needed even to fail, because Argon2id must run to produce a
    /// plausible failure. Skipping the derivation on a wrong guess would make
    /// the wrong guess fast, which is exactly backwards.
    pub fn unlock(&mut self, keyring: &Keyring, passphrase: &[u8]) -> Result<()> {
        if let Some(until) = self.locked_out_until {
            if Instant::now() < until {
                let secs = until.saturating_duration_since(Instant::now()).as_secs();
                return Err(Error::AttemptsExhausted {
                    retry_after_secs: secs,
                });
            }
        }

        match keyring.unwrap_dek(passphrase) {
            Ok(dek) => {
                // A success resets the counter, so an occasional typo does not
                // accumulate toward a lockout.
                self.failed_attempts = 0;
                self.locked_out_until = None;
                self.dek = Some(dek);
                self.opened_at = Some(Instant::now());
                Ok(())
            }
            Err(e) => {
                // Any failure counts, including "your cost parameters are
                // broken" — otherwise a damaged keyring would let an attacker
                // hammer it for free.
                self.failed_attempts = self.failed_attempts.saturating_add(1);
                if self.failed_attempts >= MAX_FAILED_ATTEMPTS {
                    self.locked_out_until = Some(Instant::now() + LOCKOUT);
                    return Err(Error::AttemptsExhausted {
                        retry_after_secs: LOCKOUT.as_secs(),
                    });
                }
                Err(e)
            }
        }
    }

    /// Lock, wiping the data key. Explicit — the only way out of `unlocked`
    /// other than dropping the session.
    pub fn lock(&mut self) -> bool {
        let was_unlocked = self.dek.is_some();
        if let Some(mut k) = self.dek.take() {
            k.wipe_now();
        }
        self.opened_at = None;
        was_unlocked
    }

    /// Refuse everything while locked, with the reason that is actually true.
    ///
    /// Used by the operations that need a caller-supplied reason, so a locked
    /// vault reports `vault_locked` rather than a generic "denied".
    pub fn deny_if_locked(&self) -> Result<()> {
        if self.is_unlocked() {
            Ok(())
        } else {
            Err(Error::Denied {
                reason: DenyReason::VaultLocked,
                detail: "unlock the vault first".into(),
            })
        }
    }

    /// Remaining lockout, for the CLI and the UI.
    pub fn lockout_remaining(&self) -> Option<Duration> {
        self.locked_out_until
            .and_then(|t| t.checked_duration_since(Instant::now()))
    }

    pub fn failed_attempts(&self) -> u32 {
        self.failed_attempts
    }

    /// Wipe and drop. Used when a process is exiting.
    pub fn shutdown(&mut self) {
        self.lock();
        self.failed_attempts = 0;
        self.locked_out_until = None;
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never prints the data key, and never prints whether a passphrase was
        // correct beyond the lock state the user already knows about.
        f.debug_struct("Session")
            .field("unlocked", &self.dek.is_some())
            .field("failed_attempts", &self.failed_attempts)
            .field("locked_out", &self.lockout_remaining().is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &[u8] = b"a decent passphrase";

    fn keyring() -> Keyring {
        Keyring::create(PASS).unwrap().0
    }

    #[test]
    fn a_new_session_is_locked() {
        let s = Session::new();
        assert!(!s.is_unlocked());
        assert_eq!(s.require_dek().unwrap_err().code(), "locked");
    }

    #[test]
    fn unlock_then_lock_roundtrips() {
        let kr = keyring();
        let mut s = Session::new();
        s.unlock(&kr, PASS).unwrap();
        assert!(s.is_unlocked());
        assert!(s.require_dek().is_ok());
        assert!(s.lock());
        assert!(!s.is_unlocked());
        assert_eq!(s.require_dek().unwrap_err().code(), "locked");
    }

    #[test]
    fn locking_twice_reports_that_nothing_changed() {
        let kr = keyring();
        let mut s = Session::new();
        s.unlock(&kr, PASS).unwrap();
        assert!(s.lock());
        assert!(!s.lock(), "a second lock must report no state change");
    }

    #[test]
    fn the_wrong_passphrase_does_not_unlock() {
        let kr = keyring();
        let mut s = Session::new();
        assert!(s.unlock(&kr, b"wrong").is_err());
        assert!(!s.is_unlocked());
    }

    #[test]
    fn a_typo_does_not_accumulate_toward_a_lockout() {
        let kr = keyring();
        let mut s = Session::new();
        for _ in 0..(MAX_FAILED_ATTEMPTS - 1) {
            assert!(s.unlock(&kr, b"wrong").is_err());
        }
        s.unlock(&kr, PASS).unwrap();
        assert_eq!(s.failed_attempts(), 0, "a success must reset the counter");
    }

    #[test]
    fn repeated_failures_trip_a_lockout_that_blocks_even_the_right_passphrase() {
        let kr = keyring();
        let mut s = Session::new();
        for _ in 0..(MAX_FAILED_ATTEMPTS - 1) {
            s.unlock(&kr, b"wrong").unwrap_err();
        }
        let err = s.unlock(&kr, b"wrong").unwrap_err();
        assert_eq!(err.code(), "attempts_exhausted");
        assert!(s.lockout_remaining().is_some());

        // The correct passphrase is refused too — otherwise the lockout would
        // not slow an attacker who knows the passphrase but wants to time
        // their attempts.
        let err = s.unlock(&kr, PASS).unwrap_err();
        assert_eq!(err.code(), "attempts_exhausted");
    }

    #[test]
    fn debug_output_has_no_key_material() {
        let kr = keyring();
        let mut s = Session::new();
        s.unlock(&kr, PASS).unwrap();
        let d = format!("{s:?}");
        assert!(d.contains("unlocked: true"));
        assert!(!d.contains("a decent passphrase"));
    }

    #[test]
    fn shutdown_clears_everything() {
        let kr = keyring();
        let mut s = Session::new();
        s.unlock(&kr, b"wrong").unwrap_err();
        s.unlock(&kr, PASS).unwrap();
        s.shutdown();
        assert!(!s.is_unlocked());
        assert_eq!(s.failed_attempts(), 0);
        assert!(s.lockout_remaining().is_none());
    }

    #[test]
    fn deny_if_locked_reports_the_real_reason() {
        let s = Session::new();
        let err = s.deny_if_locked().unwrap_err();
        match err {
            Error::Denied { reason, .. } => assert_eq!(reason, DenyReason::VaultLocked),
            other => panic!("expected a denial, got {other:?}"),
        }
    }
}
