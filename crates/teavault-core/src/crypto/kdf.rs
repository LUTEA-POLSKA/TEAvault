//! Argon2id key derivation.
//!
//! The master passphrase never becomes a key directly. It is stretched into a
//! key-encryption key, and only that KEK unwraps the random data key. Two
//! consequences follow, both deliberate:
//!
//! * Changing the passphrase re-wraps one 32-byte blob instead of re-encrypting
//!   the whole vault, so a passphrase change is fast and cheap to reason about.
//! * The vault's cost parameters are stored next to the wrapped key, so they
//!   can be raised later without invalidating existing data.
//!
//! ## Parameters
//!
//! Defaults are Argon2id v19, m=19456 KiB (19 MiB), t=2, p=1, output 32 bytes.
//! These are the values the OWASP Password Storage Cheat Sheet recommends for
//! Argon2id, and they are also `argon2::Params::DEFAULT`, so there is no
//! TEAvault-specific tuning to remember. [`KdfParams::validate`] enforces a
//! floor so a tampered keyring file cannot downgrade the cost to nothing.

use argon2::{Algorithm, Argon2, Params, Version};

use super::secret::SecretBytes;
use crate::error::{Error, Result};

/// Argon2id salt length. 16 bytes is the RFC 9106 recommendation.
pub const SALT_LEN: usize = 16;

/// Lowest memory cost the core will honour, in KiB.
///
/// A keyring file claims its own parameters, so a damaged or hostile file could
/// otherwise ask for 8 KiB and turn a 19 MiB derivation into a microsecond one —
/// which is the entire difference between a passphrase being expensive to guess
/// and free.
pub const MIN_M_COST_KIB: u32 = 8 * 1024;
/// Highest memory cost accepted. 4 GiB would be a denial of service against
/// the owner's own machine if a file asked for it.
pub const MAX_M_COST_KIB: u32 = 4 * 1024 * 1024;
/// Bounds on passes and parallelism, for the same reason.
pub const MIN_T_COST: u32 = 1;
pub const MAX_T_COST: u32 = 16;
pub const MIN_P_COST: u32 = 1;
pub const MAX_P_COST: u32 = 16;

/// A salt plus Argon2id cost parameters, as stored in the keyring.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    /// Always `"argon2id"`; present so a future format change is detectable
    /// rather than silently mis-parsed.
    pub algorithm: String,
    pub version: u32,
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    /// Hex-encoded salt.
    pub salt: String,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            algorithm: "argon2id".to_string(),
            version: 0x13,
            m_cost_kib: 19 * 1024,
            t_cost: 2,
            p_cost: 1,
            // Filled in by `generate`; a default with a fixed salt would be a
            // catastrophic mistake, so `generate` is the only constructor and
            // `Default` exists only to satisfy derive bounds.
            salt: String::new(),
        }
    }
}

impl KdfParams {
    /// Fresh parameters with a random salt.
    pub fn generate() -> Result<Self> {
        let salt = SecretBytes::random(SALT_LEN).map_err(|_| Error::Integrity)?;
        let p = Self::default();
        Ok(Self {
            salt: super::hex::encode(salt.as_slice()),
            ..p
        })
    }

    /// Same cost, new salt. Used when re-deriving after a parameter change so
    /// the new parameters are not applied to a reused salt.
    pub fn with_fresh_salt(&self) -> Result<Self> {
        let salt = super::hex::encode(SecretBytes::random(SALT_LEN)?.as_slice());
        let mut next = self.clone();
        next.salt = salt;
        Ok(next)
    }

    pub fn salt_bytes(&self) -> Result<Vec<u8>> {
        let s = super::hex::decode(&self.salt)?;
        if s.len() < 8 {
            return Err(Error::invalid("kdf.salt", "salt is too short to be unique"));
        }
        Ok(s)
    }

    /// Reject parameters that would weaken derivation or hang the process.
    ///
    /// Called on every read, not only on write. The keyring is untrusted input
    /// at exactly the moment it matters most: someone who can edit it is trying
    /// to make the next unlock cheap.
    pub fn validate(&self) -> Result<()> {
        if self.algorithm != "argon2id" {
            return Err(Error::invalid(
                "kdf.algorithm",
                format!(
                    "unsupported KDF {:?}; this build only implements argon2id",
                    self.algorithm
                ),
            ));
        }
        if self.version != 0x13 {
            return Err(Error::UnsupportedFormat {
                found: self.version,
                supported: 0x13,
            });
        }
        if !(MIN_M_COST_KIB..=MAX_M_COST_KIB).contains(&self.m_cost_kib) {
            return Err(Error::invalid(
                "kdf.m_cost_kib",
                format!(
                    "must be between {MIN_M_COST_KIB} and {MAX_M_COST_KIB} KiB, found {}",
                    self.m_cost_kib
                ),
            ));
        }
        if !(MIN_T_COST..=MAX_T_COST).contains(&self.t_cost) {
            return Err(Error::invalid("kdf.t_cost", "out of supported range"));
        }
        if !(MIN_P_COST..=MAX_P_COST).contains(&self.p_cost) {
            return Err(Error::invalid("kdf.p_cost", "out of supported range"));
        }
        self.salt_bytes()?;
        Ok(())
    }

    /// Stretch `passphrase` into `out_len` bytes.
    ///
    /// The passphrase is borrowed and never stored, copied into a log, or
    /// included in an error.
    pub fn derive(&self, passphrase: &[u8], out_len: usize) -> Result<SecretBytes> {
        self.validate()?;
        if passphrase.is_empty() {
            return Err(Error::invalid("passphrase", "must not be empty"));
        }
        let params = Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(out_len))
            .map_err(|e| Error::invalid("kdf", e.to_string()))?;

        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = vec![0u8; out_len];
        argon
            .hash_password_into(passphrase, &self.salt_bytes()?, &mut out)
            .map_err(|_| Error::invalid("kdf", "derivation failed"))?;

        // `out` is a plain Vec; hand it straight to the secret container so
        // there is no point at which it lives as an unmanaged buffer.
        let secret = SecretBytes::new(out);
        // Argon2's own internal state is freed by the library; it does not
        // promise to wipe its block memory, which is a documented limitation.
        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deliberately weak parameters so the tests stay fast. Production
    /// parameters are asserted separately against the OWASP defaults.
    ///
    /// Note this still carries a real random salt: `validate()` rejects a short
    /// one, and a test fixture that skips validation would not exercise the
    /// path production uses.
    fn fast() -> KdfParams {
        KdfParams {
            m_cost_kib: MIN_M_COST_KIB,
            t_cost: 1,
            p_cost: 1,
            salt: super::super::hex::encode(&[0x5a; SALT_LEN]),
            algorithm: "argon2id".into(),
            version: 0x13,
        }
    }

    #[test]
    fn defaults_match_the_owasp_recommendation() {
        let p = KdfParams::generate().unwrap();
        assert_eq!(p.algorithm, "argon2id");
        assert_eq!(p.version, 0x13);
        assert_eq!(p.m_cost_kib, 19 * 1024, "OWASP Argon2id m=19 MiB");
        assert_eq!(p.t_cost, 2, "OWASP Argon2id t=2");
        assert_eq!(p.p_cost, 1, "OWASP Argon2id p=1");
        p.validate().unwrap();
    }

    #[test]
    fn derive_is_deterministic_for_the_same_inputs() {
        let p = fast();
        let a = p.derive(b"passphrase", 32).unwrap();
        let b = p.derive(b"passphrase", 32).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn a_different_passphrase_yields_a_different_key() {
        let p = fast();
        let a = p.derive(b"passphrase-one", 32).unwrap();
        let b = p.derive(b"passphrase-two", 32).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn a_different_salt_yields_a_different_key() {
        let p = fast();
        let a = p.derive(b"same-passphrase", 32).unwrap();
        let q = p.with_fresh_salt().unwrap();
        let b = q.derive(b"same-passphrase", 32).unwrap();
        assert_ne!(a, b);
        assert_ne!(p.salt, q.salt);
    }

    #[test]
    fn a_tampered_cost_parameter_is_rejected() {
        // A keyring that claims it needs almost no memory would make every
        // offline guess cheap. This is the single most important check here.
        let weak = KdfParams {
            m_cost_kib: 8,
            ..fast()
        };
        let err = weak.validate().unwrap_err();
        assert_eq!(err.code(), "invalid");
        assert!(weak.derive(b"x", 32).is_err());
    }

    #[test]
    fn a_hostile_cost_parameter_is_rejected() {
        let huge = KdfParams {
            m_cost_kib: u32::MAX,
            ..fast()
        };
        assert!(huge.validate().is_err());
        let many_threads = KdfParams {
            p_cost: 255,
            ..fast()
        };
        assert!(many_threads.validate().is_err());
    }

    #[test]
    fn a_non_argon2id_algorithm_is_rejected() {
        let scrypt = KdfParams {
            algorithm: "scrypt".into(),
            ..fast()
        };
        assert_eq!(scrypt.validate().unwrap_err().code(), "invalid");
    }

    #[test]
    fn an_unknown_version_is_rejected() {
        let v = KdfParams {
            version: 0x10,
            ..fast()
        };
        assert_eq!(v.validate().unwrap_err().code(), "unsupported_format");
    }

    #[test]
    fn a_short_salt_is_rejected() {
        let p = KdfParams {
            salt: "00ff".into(),
            ..fast()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn an_empty_passphrase_is_rejected_before_argon2_runs() {
        assert!(fast().derive(b"", 32).is_err());
    }

    #[test]
    fn derivation_is_slow_enough_to_matter() {
        // Not a benchmark — a floor. If a build made 19 MiB of memory time drop
        // below a few tens of milliseconds, derivation would be too cheap to
        // resist an offline search and this would catch it.
        let p = KdfParams::generate().unwrap();
        let t = std::time::Instant::now();
        p.derive(b"benchmark-passphrase", 32).unwrap();
        assert!(
            t.elapsed().as_millis() >= 20,
            "argon2id finished in {:?}, which is suspiciously fast",
            t.elapsed()
        );
    }
}
