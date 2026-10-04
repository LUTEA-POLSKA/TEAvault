//! DPAPI-backed protection for the audit chain key.
//!
//! # Why this exists
//!
//! The audit log's SHA-256 chain alone is defeated by anyone who can simply
//! recompute it: the digests are not secret, and rewriting the file is a loop of
//! hashing. The MAC over the same payload is what closes that gap, and it is only
//! meaningful if the key behind it cannot be read by the rewriting party.
//!
//! DPAPI provides exactly that, and — this is the part that matters — it does
//! **not** weaken the vault's passphrase barrier. DPAPI unwraps for the Windows
//! account that protected the blob, which is the same account that runs
//! TEAvault. That is weaker than the passphrase, and it is deliberately kept in a
//! separate system from the data key, which requires the passphrase and is never
//! handed to DPAPI.
//!
//! # What it does not buy
//!
//! An attacker who fully controls the user account can call
//! `CryptUnprotectData` themselves. So this is tamper-*evidence*, not
//! tamper-proofing: it stops an unsophisticated rewrite, an unrelated tool, and a
//! second local account. It does not stop the owner of the account. See
//! `THREAT_MODEL.md`.

use std::sync::Mutex;

use teavault_core::{
    audit::ChainKeyProtector,
    error::{Error, Result},
};
use windows::Win32::{
    Foundation::{LocalFree, HLOCAL},
    Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    },
};

/// The DPAPI implementation.
#[derive(Default)]
pub struct DpapiProtector {
    /// `CryptProtectData`/`CryptUnprotectData` have no thread-affinity guarantee
    /// documented, and both take an out-pointer the caller must free. Serialising
    /// them keeps the ownership handling obvious: exactly one blob in flight, so
    /// exactly one `LocalFree` to pair with it.
    _serialised: Mutex<()>,
}

impl DpapiProtector {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Win32's in/out blob type. `cbData`/`pbData` are a length and a pointer — the
/// same shape as `DATA_BLOB` in the Windows headers.
struct Blob {
    data: Vec<u8>,
}

impl Blob {
    fn as_crypt(&self) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: self.data.len() as u32,
            pbData: self.data.as_ptr() as *mut u8,
        }
    }
}

/// Frees a blob Win32 allocated for us.
///
/// Without this every `CryptUnprotectData` leaks the plaintext chain key into the
/// daemon's heap, which is precisely the thing the zeroising containers elsewhere
/// exist to avoid.
struct LocalBlob(CRYPT_INTEGER_BLOB);

impl Drop for LocalBlob {
    fn drop(&mut self) {
        if !self.0.pbData.is_null() {
            // Zero the buffer *before* releasing it. Win32 documents the
            // returned blob as the caller's to free; whether it clears it first
            // is not guaranteed.
            unsafe {
                std::ptr::write_bytes(self.0.pbData, 0, self.0.cbData as usize);
                let _ = LocalFree(Some(HLOCAL(self.0.pbData as *mut _)));
            }
        }
    }
}

impl ChainKeyProtector for DpapiProtector {
    fn protect(&self, key: &[u8]) -> Result<Vec<u8>> {
        let _guard = self._serialised.lock().unwrap_or_else(|p| p.into_inner());

        let input = Blob { data: key.to_vec() };
        let mut out = CRYPT_INTEGER_BLOB::default();

        unsafe {
            CryptProtectData(
                &input.as_crypt(),
                None, // no description: it would be readable metadata
                None, // no optional entropy
                None, // no reserved
                None, // no prompt struct
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
            .map_err(|e| Error::io("dpapi", std::io::Error::other(e.to_string())))?;

            let owned = LocalBlob(out);
            let len = owned.0.cbData as usize;
            let mut sealed = Vec::with_capacity(len);
            sealed.extend_from_slice(std::slice::from_raw_parts(owned.0.pbData, len));
            Ok(sealed)
        }
    }

    fn unprotect(&self, blob: &[u8]) -> Result<Vec<u8>> {
        let _guard = self._serialised.lock().unwrap_or_else(|p| p.into_inner());

        let input = Blob {
            data: blob.to_vec(),
        };
        let mut out = CRYPT_INTEGER_BLOB::default();

        unsafe {
            CryptUnprotectData(
                &input.as_crypt(),
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
            .map_err(|_| {
                // The failure mode is deliberately undifferentiated. "Wrong
                // account", "not a DPAPI blob" and "tampered" all mean the same
                // thing to a caller, and distinguishing them would tell an
                // attacker which of the three they achieved.
                Error::Malformed("the audit key could not be unwrapped".into())
            })?;

            let owned = LocalBlob(out);
            let len = owned.0.cbData as usize;
            let mut key = Vec::with_capacity(len);
            key.extend_from_slice(std::slice::from_raw_parts(owned.0.pbData, len));
            // Wrapped so it wipes on drop like every other secret here.
            Ok(teavault_core::crypto::SecretBytes::new(key).into_inner())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blob_protected_here_unwraps_here() {
        let p = DpapiProtector::new();
        let key = b"thirty-two-byte-chain-key-00000";
        let sealed = p.protect(key).unwrap();
        assert_ne!(sealed, key.to_vec(), "the blob must not be the key");
        assert!(p.unprotect(&sealed).unwrap() == key.to_vec());
    }

    #[test]
    fn the_blob_is_not_the_key_in_any_readable_form() {
        let p = DpapiProtector::new();
        let key = b"thirty-two-byte-chain-key-00000";
        let sealed = p.protect(key).unwrap();
        let text = String::from_utf8_lossy(&sealed);
        assert!(!text.contains("chain-key"));
    }

    #[test]
    fn a_tampered_blob_is_refused_rather_than_returning_garbage() {
        let p = DpapiProtector::new();
        let mut sealed = p.protect(b"thirty-two-byte-chain-key-00000").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(p.unprotect(&sealed).is_err());
    }

    #[test]
    fn arbitrary_bytes_are_refused() {
        let p = DpapiProtector::new();
        assert!(p.unprotect(b"not a dpapi blob").is_err());
    }

    #[test]
    fn two_protections_of_the_same_key_differ() {
        // DPAPI salts its output, which is what stops an observer from noticing
        // that the chain key was rewritten unchanged.
        let p = DpapiProtector::new();
        let a = p.protect(b"thirty-two-byte-chain-key-00000").unwrap();
        let b = p.protect(b"thirty-two-byte-chain-key-00000").unwrap();
        assert_ne!(a, b);
    }
}
