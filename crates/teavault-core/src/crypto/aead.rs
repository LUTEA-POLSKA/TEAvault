//! Authenticated encryption.
//!
//! AES-256-GCM throughout, chosen over alternatives for one reason above all:
//! it is the AEAD with the broadest hardware support and the longest deployed
//! history, so it is the one whose failure modes are actually understood. It
//! is a NIST SP 800-38D construction and is not TEAvault's own.
//!
//! Two decisions worth stating:
//!
//! * **A random 96-bit nonce per sealing operation.** The library generates it
//!   from the OS CSPRNG. GCM's catastrophic failure is nonce reuse under one
//!   key, so the bound has to be stated rather than waved at: a 96-bit random
//!   nonce keeps collision probability below 2⁻³² across ~4 billion
//!   operations under a single key, which is far beyond any realistic vault
//!   lifetime. (Were the count ever to approach that, the correct fix is
//!   switching to ChaCha20-Poly1305 with a counter nonce, not raising a
//!   threshold.) The DEK is regenerated on every `change-passphrase`, which
//!   resets the per-key budget as well.
//! * **Associated data is mandatory and caller-supplied.** Callers authenticate
//!   the *purpose* and *identity* of a ciphertext, not just its bytes. A
//!   vault record seals with its entry id, so a ciphertext cannot be moved to a
//!   different entry; the keyring seals with a fixed domain string, so vault
//!   material cannot be replayed as keyring material.

use aes_gcm::{
    aead::{Aead, Key, KeyInit},
    Aes256Gcm, Nonce,
};

use super::secret::SecretBytes;
use crate::error::{Error, Result};

/// Length of the GCM nonce in bytes.
pub const NONCE_LEN: usize = 12;
/// Length of the GCM authentication tag in bytes.
pub const TAG_LEN: usize = 16;
/// Data key length. AES-256.
pub const KEY_LEN: usize = 32;

/// A ciphertext together with the nonce it needs to open.
///
/// The authentication tag is appended to `ciphertext` rather than kept
/// separate, so there is exactly one representation of a sealed blob on disk
/// and no way to store one that has been stripped of its tag.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Sealed {
    /// Hex-encoded nonce.
    pub nonce: String,
    /// Hex-encoded ciphertext, tag included.
    pub ciphertext: String,
}

impl Sealed {
    pub fn nonce_bytes(&self) -> Result<[u8; NONCE_LEN]> {
        let raw = super::hex::decode(&self.nonce)?;
        <[u8; NONCE_LEN]>::try_from(raw.as_slice())
            .map_err(|_| Error::Malformed("sealed nonce has the wrong length".into()))
    }

    pub fn ciphertext_bytes(&self) -> Result<Vec<u8>> {
        super::hex::decode(&self.ciphertext)
    }
}

fn cipher_from(key: &SecretBytes) -> Result<Aes256Gcm> {
    if key.len() != KEY_LEN {
        return Err(Error::invalid("key", "data key must be exactly 32 bytes"));
    }
    // `TryFrom` rather than the deprecated `from_slice`, which panics on a
    // length mismatch. The length is checked above, but a panic in a crypto
    // path is a worse failure mode than an error.
    let k = Key::<Aes256Gcm>::try_from(key.as_slice())
        .map_err(|_| Error::invalid("key", "data key must be exactly 32 bytes"))?;
    Ok(Aes256Gcm::new(&k))
}

/// A fresh 96-bit nonce from the OS CSPRNG.
///
/// Written out explicitly rather than reaching for the `Generate` trait,
/// whose convenience form panics if the OS random source fails. A vault must
/// return an error there, not abort the process.
fn fresh_nonce() -> Result<[u8; NONCE_LEN]> {
    let mut n = [0u8; NONCE_LEN];
    getrandom::fill(&mut n).map_err(|_| Error::Integrity)?;
    Ok(n)
}

/// Encrypt `plaintext` under `key`, authenticating `aad`.
///
/// The plaintext is borrowed, never copied, on the way in.
pub fn seal(key: &SecretBytes, aad: &[u8], plaintext: &[u8]) -> Result<Sealed> {
    let cipher = cipher_from(key)?;
    let nonce_bytes = fresh_nonce()?;
    let nonce = Nonce::try_from(&nonce_bytes[..]).map_err(|_| Error::Integrity)?;
    let out = cipher
        .encrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Integrity)?;
    Ok(Sealed {
        nonce: super::hex::encode(&nonce_bytes),
        ciphertext: super::hex::encode(&out),
    })
}

/// Decrypt a sealed blob.
///
/// Every failure mode — wrong key, wrong nonce, flipped ciphertext bit,
/// altered AAD, truncated tag — collapses into [`Error::Integrity`]. Reporting
/// them distinctly would be an oracle: an attacker could tell "you got the
/// structure right but the key wrong" from "the file is damaged", which is one
/// bit of information about the key they did not have.
pub fn open(key: &SecretBytes, aad: &[u8], sealed: &Sealed) -> Result<SecretBytes> {
    let cipher = cipher_from(key)?;
    let nonce_bytes = sealed.nonce_bytes()?;
    let nonce = Nonce::try_from(&nonce_bytes[..]).map_err(|_| Error::Integrity)?;
    let ciphertext = sealed.ciphertext_bytes()?;
    if ciphertext.len() < TAG_LEN {
        return Err(Error::Integrity);
    }
    let mut plain = cipher
        .decrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Integrity)?;
    // `decrypt` returns a Vec the crate does not wipe. Wrap it before it can
    // ever be observed, so there is no window where a plain Vec of plaintext
    // exists.
    let secret = SecretBytes::new(std::mem::take(&mut plain));
    Ok(secret)
}

/// Generate a fresh random data key.
pub fn generate_data_key() -> Result<SecretBytes> {
    let mut k = [0u8; KEY_LEN];
    getrandom::fill(&mut k).map_err(|_| Error::Integrity)?;
    Ok(SecretBytes::new(k.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SecretBytes {
        generate_data_key().unwrap()
    }

    fn aad() -> &'static [u8] {
        b"teavault:test:vault"
    }

    #[test]
    fn roundtrip_returns_the_original_bytes() {
        let k = key();
        let msg = b"sk-proj-not-a-real-key-0000000000";
        let sealed = seal(&k, aad(), msg).unwrap();
        let opened = open(&k, aad(), &sealed).unwrap();
        assert_eq!(opened.as_slice(), msg);
    }

    #[test]
    fn ciphertext_does_not_contain_the_plaintext() {
        let k = key();
        let sealed = seal(&k, aad(), b"PLAINTEXT-MARKER").unwrap();
        assert!(!sealed.ciphertext.contains("504c4149"));
        assert!(sealed.ciphertext.len() > "PLAINTEXT-MARKER".len() * 2);
    }

    #[test]
    fn a_flipped_ciphertext_bit_is_rejected() {
        let k = key();
        let mut sealed = seal(&k, aad(), b"hello world").unwrap();
        // Flip one hex nibble in the middle of the ciphertext.
        let mut raw = super::super::hex::decode(&sealed.ciphertext).unwrap();
        let mid = raw.len() / 2;
        raw[mid] ^= 0x01;
        sealed.ciphertext = super::super::hex::encode(&raw);

        let err = open(&k, aad(), &sealed).unwrap_err();
        assert_eq!(err.code(), "integrity");
    }

    #[test]
    fn a_flipped_nonce_bit_is_rejected() {
        let k = key();
        let mut sealed = seal(&k, aad(), b"hello world").unwrap();
        let mut raw = super::super::hex::decode(&sealed.nonce).unwrap();
        raw[0] ^= 0x80;
        sealed.nonce = super::super::hex::encode(&raw);

        assert_eq!(open(&k, aad(), &sealed).unwrap_err().code(), "integrity");
    }

    #[test]
    fn altered_associated_data_is_rejected() {
        // This is the property that stops a ciphertext being replayed into a
        // different context — a different entry, or a different file.
        let k = key();
        let sealed = seal(&k, b"context:A", b"hello world").unwrap();
        assert_eq!(
            open(&k, b"context:B", &sealed).unwrap_err().code(),
            "integrity"
        );
    }

    #[test]
    fn a_different_key_is_rejected() {
        let sealed = seal(&key(), aad(), b"hello").unwrap();
        assert_eq!(
            open(&key(), aad(), &sealed).unwrap_err().code(),
            "integrity"
        );
    }

    #[test]
    fn a_truncated_tag_is_rejected() {
        let k = key();
        let mut sealed = seal(&k, aad(), b"hello").unwrap();
        let raw = super::super::hex::decode(&sealed.ciphertext).unwrap();
        sealed.ciphertext = super::super::hex::encode(&raw[..raw.len() - 1]);
        assert_eq!(open(&k, aad(), &sealed).unwrap_err().code(), "integrity");
    }

    #[test]
    fn every_distinct_sealing_produces_a_distinct_nonce() {
        let k = key();
        let mut nonces = std::collections::BTreeSet::new();
        for _ in 0..256 {
            nonces.insert(seal(&k, aad(), b"same plaintext").unwrap().nonce);
        }
        // Identical plaintexts must not produce identical blobs, or an observer
        // could tell which entries share a value.
        assert_eq!(nonces.len(), 256);
    }

    #[test]
    fn a_wrong_length_key_is_rejected_before_any_crypto_runs() {
        let short = SecretBytes::new(vec![0u8; 16]);
        assert_eq!(seal(&short, aad(), b"x").unwrap_err().code(), "invalid");
    }
}
