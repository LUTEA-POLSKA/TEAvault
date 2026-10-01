//! Unlock, lock, auto-lock and failed-attempt limiting.
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
//! ## Auto-lock without polling
//!
//! [`Session::seconds_until_auto_lock`] is a pure function of the last activity
//! timestamp. The daemon evaluates it when it already has a reason to wake —
//! on a request, on a tray click, on the session-notification message. Nothing
//! wakes up on a timer to check, so an idle vault costs no CPU at all. The
//! consequence is that auto-lock fires at the *next* event rather than to the
//! millisecond, which for a vault is harmless: nothing can be read between two
//! events.

use std::time::{Duration, Instant};

use crate::{
    crypto::keyring::Keyring,
    crypto::secret::SecretBytes,
    error::{DenyReason, Error, Result},
    settings::AutoLock,
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
    /// Monotonic clock value of the last activity, for auto-lock arithmetic.
    last_activity: Option<Instant>,
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
            last_activity: None,
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
                let now = Instant::now();
                self.opened_at = Some(now);
                self.last_activity = Some(now);
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

    /// Lock, wiping the data key.
    pub fn lock(&mut self) -> bool {
        let was_unlocked = self.dek.is_some();
        if let Some(mut k) = self.dek.take() {
            k.wipe_now();
        }
        self.opened_at = None;
        self.last_activity = None;
        was_unlocked
    }

    /// Record that the user did something, resetting the idle timer.
    pub fn touch(&mut self) {
        if self.is_unlocked() {
            self.last_activity = Some(Instant::now());
        }
    }

    /// Whether the idle timeout has elapsed.
    pub fn should_auto_lock(&self, auto_lock: &AutoLock) -> bool {
        if !self.is_unlocked() {
            return false;
        }
        let Some(timeout) = auto_lock.seconds() else {
            return false;
        };
        match self.last_activity {
            Some(t) => t.elapsed() >= Duration::from_secs(timeout),
            // Unlocked with no recorded activity should not linger forever.
            None => true,
        }
    }

    /// Lock if the idle timeout has elapsed. Returns whether it locked.
    pub fn auto_lock_if_due(&mut self, auto_lock: &AutoLock) -> bool {
        if self.should_auto_lock(auto_lock) {
            self.lock();
            true
        } else {
            false
        }
    }

    /// Remaining idle time, for the UI countdown. `None` when not applicable.
    pub fn seconds_until_auto_lock(&self, auto_lock: &AutoLock) -> Option<u64> {
        if !self.is_unlocked() {
            return None;
        }
        let timeout = auto_lock.seconds()?;
        let elapsed = self.last_activity.map(|t| t.elapsed()).unwrap_or_default();
        Some(timeout.saturating_sub(elapsed.as_secs()))
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
    fn auto_lock_fires_once_the_timeout_has_elapsed_and_locks_the_vault() {
        let kr = keyring();
        let mut s = Session::new();
        s.unlock(&kr, PASS).unwrap();

        // A timeout that has certainly passed. Settings validation rejects a
        // 0-second timeout as a *user-facing* value, but the session has to
        // behave correctly for any timeout it is handed, so it is tested here.
        assert!(s.should_auto_lock(&AutoLock::AfterSeconds(0)));
        assert!(s.auto_lock_if_due(&AutoLock::AfterSeconds(0)));
        assert!(
            !s.is_unlocked(),
            "auto-lock must actually lock, not just report"
        );
    }

    #[test]
    fn auto_lock_does_not_fire_before_the_timeout() {
        let kr = keyring();
        let mut s = Session::new();
        s.unlock(&kr, PASS).unwrap();
        std::thread::sleep(Duration::from_millis(20));

        let soon = AutoLock::AfterSeconds(60);
        assert!(!s.should_auto_lock(&soon));
        assert!(!s.auto_lock_if_due(&soon));
        assert!(s.is_unlocked());
    }

    #[test]
    fn auto_lock_never_fires_when_the_user_disabled_it() {
        let kr = keyring();
        let mut s = Session::new();
        s.unlock(&kr, PASS).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        assert!(!s.should_auto_lock(&AutoLock::Never));
        assert!(!s.auto_lock_if_due(&AutoLock::Never));
        assert!(s.is_unlocked());
    }

    #[test]
    fn touching_resets_the_idle_timer() {
        let kr = keyring();
        let mut s = Session::new();
        s.unlock(&kr, PASS).unwrap();
        std::thread::sleep(Duration::from_millis(30));
        s.touch();
        let one_second = AutoLock::AfterSeconds(10);
        assert!(s
            .seconds_until_auto_lock(&one_second)
            .map(|s| s >= 9)
            .unwrap_or(false));
    }

    #[test]
    fn the_idle_countdown_is_none_while_locked() {
        let s = Session::new();
        assert_eq!(s.seconds_until_auto_lock(&AutoLock::AfterSeconds(60)), None);
        assert!(!s.should_auto_lock(&AutoLock::AfterSeconds(1)));
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
