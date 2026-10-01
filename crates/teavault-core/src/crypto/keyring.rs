//! The key hierarchy.
//!
//! ```text
//!   master passphrase ──Argon2id(salt, m, t, p)──▶ KEK  (derived, never stored)
//!                                                     │
//!                                     AES-256-GCM     │  wraps exactly 32 bytes
//!                                                     ▼
//!                                                 data key (random, at creation)
//!                                                     │
//!                                     AES-256-GCM     │  seals each vault record,
//!                                                     │  bound to its entry id
//!                                                     ▼
//!                                              encrypted entries
//! ```
//!
//! What is on disk:
//!
//! * `vault.keyring` — KDF parameters, the salt, and the wrapped data key.
//!   Everything in it is either public or ciphertext. An attacker who copies it
//!   learns nothing but the cost of a guess.
//! * `vault.data` — the sealed records, each with its own nonce, authenticated
//!   together with its entry id so records cannot be swapped.
//!
//! What is never on disk, in a log, or in a config file: the passphrase, the
//! KEK, or the unwrapped data key. The data key exists only inside an unlocked
//! session and is wiped when the session ends.
//!
//! ## Why the data key is random rather than derived
//!
//! A derived data key would mean the passphrase could be changed only by
//! re-encrypting every entry — a slow, failure-prone operation with a window in
//! which a crash loses keys. A random data key changes cost from *N entries* to
//! *32 bytes*, and it means the entries are protected by a key that has no
//! relationship to the human's memory of their passphrase beyond the wrap.
//!
//! ## Recovery
//!
//! There is none, by design. Losing the passphrase loses the data key, and no
//! backdoor, universal key or escrow exists. This is stated to the user before
//! the vault is created, not discovered afterwards.

use serde::{Deserialize, Serialize};

use super::{
    aead::{self, Sealed},
    kdf::KdfParams,
    secret::SecretBytes,
};
use crate::error::{Error, Result};

/// The on-disk keyring. Public parameters plus one wrapped blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keyring {
    /// Storage format version, checked against the crate's.
    pub format_version: u32,
    pub kdf: KdfParams,
    /// The data key, sealed under the passphrase-derived KEK.
    pub wrapped_dek: Sealed,
    /// RFC 3339 timestamp, for display only.
    pub created_at: String,
    /// When the data key was last re-wrapped, for display only.
    pub rewrapped_at: String,
}

/// Domain separator for the keyring seal.
///
/// Authenticated data, not encryption scope: it means a blob sealed as a
/// keyring can never be opened as a vault record or vice versa, even though
/// both are AES-256-GCM under a 32-byte key.
pub const KEYRING_AAD: &[u8] = b"teavault:v1:keyring:data-key";

impl Keyring {
    /// Create a brand-new vault: fresh parameters, fresh salt, fresh data key.
    ///
    /// Returns the keyring to persist *and* the data key to use for this
    /// session. The caller is responsible for writing the keyring; if it
    /// fails to do so, the data key is dropped and wiped with it.
    pub fn create(passphrase: &[u8]) -> Result<(Self, SecretBytes)> {
        let kdf = KdfParams::generate()?;
        let dek = aead::generate_data_key()?;
        let kek = kdf.derive(passphrase, aead::KEY_LEN)?;
        let wrapped = aead::seal(&kek, KEYRING_AAD, dek.as_slice())?;

        let now = crate::model::now_rfc3339();
        let kr = Self {
            format_version: crate::PROTOCOL_VERSION,
            kdf,
            wrapped_dek: wrapped,
            created_at: now.clone(),
            rewrapped_at: now,
        };
        Ok((kr, dek))
    }

    /// Unwrap the data key.
    ///
    /// Derivation is attempted on every call, including with a wrong
    /// passphrase. There is no "is this the right passphrase" shortcut,
    /// because such a shortcut is a verification oracle.
    ///
    /// A failure is reported as [`Error::InvalidPassphrase`] whether the
    /// passphrase was wrong or the file was damaged. Distinguishing them would
    /// tell an offline attacker which situation they are in, and there is no
    /// different recovery action for the user either way.
    pub fn unwrap_dek(&self, passphrase: &[u8]) -> Result<SecretBytes> {
        if self.format_version > crate::PROTOCOL_VERSION {
            return Err(Error::UnsupportedFormat {
                found: self.format_version,
                supported: crate::PROTOCOL_VERSION,
            });
        }
        // A damaged or downgraded parameter set is reported as a refusal, not
        // as a passphrase failure: the file is the problem, and saying
        // otherwise sends the user round in circles typing the same phrase.
        self.kdf.validate()?;

        let kek = self.kdf.derive(passphrase, aead::KEY_LEN)?;
        aead::open(&kek, KEYRING_AAD, &self.wrapped_dek).map_err(|_| Error::InvalidPassphrase)
    }

    /// Re-wrap the *same* data key under a new passphrase.
    ///
    /// Note what this does not do: it does not generate a new data key. The
    /// entries are untouched, and there is no re-encryption window in which a
    /// crash could lose them.
    ///
    /// The caller supplies the data key, which means it must already be
    /// unlocked. That is deliberate — a passphrase change is an authenticated
    /// operation, not an unauthenticated one.
    pub fn rewrap(&mut self, dek: &SecretBytes, new_passphrase: &[u8]) -> Result<()> {
        if dek.len() != aead::KEY_LEN {
            return Err(Error::invalid("data key", "must be 32 bytes"));
        }
        // New salt: re-deriving under a reused salt would leave two passphrases
        // whose stretched outputs are related.
        self.kdf = self.kdf.with_fresh_salt()?;
        let kek = self.kdf.derive(new_passphrase, aead::KEY_LEN)?;
        self.wrapped_dek = aead::seal(&kek, KEYRING_AAD, dek.as_slice())?;
        self.rewrapped_at = crate::model::now_rfc3339();
        Ok(())
    }

    /// The cost of one unlock attempt, for display before the user commits to
    /// typing a passphrase.
    pub fn cost_summary(&self) -> String {
        format!(
            "argon2id, {} MiB memory, {} passes, {} lanes",
            self.kdf.m_cost_kib / 1024,
            self.kdf.t_cost,
            self.kdf.p_cost
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &[u8] = b"correct horse battery staple";

    #[test]
    fn create_then_unwrap_returns_the_data_key() {
        let (kr, dek) = Keyring::create(PASS).unwrap();
        assert_eq!(dek.len(), aead::KEY_LEN);
        let again = kr.unwrap_dek(PASS).unwrap();
        assert_eq!(again, dek);
    }

    #[test]
    fn the_wrong_passphrase_is_refused() {
        let (kr, _) = Keyring::create(PASS).unwrap();
        let err = kr.unwrap_dek(b"wrong passphrase").unwrap_err();
        assert_eq!(err.code(), "invalid_passphrase");
    }

    #[test]
    fn a_wrong_passphrase_and_a_tampered_blob_are_indistinguishable() {
        // If these produced different errors, an offline attacker could tell
        // "I have the right idea but wrong guess" from "this file is garbage",
        // and the first is worth searching for.
        let (kr, _) = Keyring::create(PASS).unwrap();
        let mut tampered = kr.clone();
        let mut ct = tampered.wrapped_dek.ciphertext_bytes().unwrap();
        ct[0] ^= 0x01;
        tampered.wrapped_dek.ciphertext = super::super::hex::encode(&ct);

        assert_eq!(
            kr.unwrap_dek(b"nope").unwrap_err().code(),
            tampered.unwrap_dek(PASS).unwrap_err().code()
        );
    }

    #[test]
    fn a_tampered_salt_is_refused_rather_than_weakly_derived() {
        let (kr, _) = Keyring::create(PASS).unwrap();
        let mut t = kr.clone();
        t.kdf.salt = "0011223344556677".into();
        // A valid salt yields a different KEK, so the unwrap fails as a
        // passphrase error — and the point is that it does not succeed.
        assert!(t.unwrap_dek(PASS).is_err());
    }

    #[test]
    fn downgraded_cost_parameters_are_refused_on_read() {
        let (kr, _) = Keyring::create(PASS).unwrap();
        let mut t = kr.clone();
        t.kdf.m_cost_kib = 1;
        let err = t.unwrap_dek(PASS).unwrap_err();
        assert_eq!(err.code(), "invalid");
    }

    #[test]
    fn an_unknown_algorithm_is_refused_on_read() {
        let (kr, _) = Keyring::create(PASS).unwrap();
        let mut t = kr.clone();
        t.kdf.algorithm = "md5".into();
        assert_eq!(t.unwrap_dek(PASS).unwrap_err().code(), "invalid");
    }

    #[test]
    fn a_future_format_version_is_refused() {
        let (mut kr, _) = Keyring::create(PASS).unwrap();
        kr.format_version = 99;
        assert_eq!(
            kr.unwrap_dek(PASS).unwrap_err().code(),
            "unsupported_format"
        );
    }

    #[test]
    fn rewrap_changes_the_passphrase_without_changing_the_data_key() {
        let (mut kr, dek) = Keyring::create(PASS).unwrap();
        let old_salt = kr.kdf.salt.clone();
        kr.rewrap(&dek, b"a different passphrase").unwrap();

        assert_ne!(kr.kdf.salt, old_salt, "rewrap must use a fresh salt");
        assert!(
            kr.unwrap_dek(PASS).is_err(),
            "old passphrase must stop working"
        );
        assert_eq!(kr.unwrap_dek(b"a different passphrase").unwrap(), dek);
    }

    #[test]
    fn the_keyring_never_contains_anything_resembling_a_secret() {
        // Guards against someone later adding a debug field or a cached copy.
        let (kr, dek) = Keyring::create(PASS).unwrap();
        let json = serde_json::to_string(&kr).unwrap();
        assert!(
            !json.contains("correct horse"),
            "keyring leaked the passphrase"
        );
        assert!(!json.contains(&super::super::hex::encode(dek.as_slice())));
        for field in json.split('"') {
            assert!(
                !field.starts_with("dek") && field != "data_key",
                "a plaintext data key field appeared in the keyring"
            );
        }
    }

    #[test]
    fn an_empty_passphrase_cannot_create_a_vault() {
        assert!(Keyring::create(b"").is_err());
    }
}
