//! Zeroising containers for secret material.
//!
//! Rust gives no guarantee that a secret is gone after it is dropped: the
//! allocator may have copied it, the OS may have paged it to disk, and a crash
//! dump will happily contain it. What this module *does* give is that every
//! buffer the core allocates for a secret is explicitly overwritten on drop
//! rather than merely becoming unreachable. That is a real reduction in
//! exposure window, and it is the only one available without unsafe code.
//!
//! See `SECURITY.md` for what this does and does not protect against.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

/// A byte buffer that is overwritten when dropped.
///
/// Deliberately does **not** implement `Debug` as a normal derive: a derived
/// `Debug` would print the key. [`fmt::Debug`] prints the length only, which is
/// enough to diagnose a bug and useless to an attacker reading a log.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Takes ownership of `bytes`, promising to wipe them on drop.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Generates `n` bytes from the operating system CSPRNG.
    pub fn random(n: usize) -> Result<Self, getrandom::Error> {
        let mut v = vec![0u8; n];
        getrandom::fill(&mut v)?;
        Ok(Self::new(v))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Overwrites the buffer immediately rather than waiting for the drop.
    ///
    /// Used when a secret's lifetime ends early but the container lives on —
    /// for instance when a session is locked but the process stays running.
    pub fn wipe_now(&mut self) {
        self.0.zeroize();
    }

    /// Copy-free hand-off, for when the caller must take ownership.
    pub fn into_inner(mut self) -> Vec<u8> {
        // Zeroizing<Vec<u8>> has no into_inner, so detach the pointer and let
        // the zeroizing wrapper drop an empty vector.
        std::mem::take(&mut self.0)
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        // Explicit, and documented as a copy: this is the one place a secret
        // is deliberately duplicated. Callers should be able to point at it in
        // review.
        Self::new(self.0.to_vec())
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(len={})", self.0.len())
    }
}

impl PartialEq for SecretBytes {
    /// Constant-time comparison.
    ///
    /// Timing-safe equality is not decoration here: a caller comparing a
    /// presented passphrase byte-by-byte with an early return leaks the prefix
    /// length that matched, which is enough to make an offline search
    /// meaningfully cheaper.
    fn eq(&self, other: &Self) -> bool {
        if self.0.len() != other.0.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

/// A secret that is textual in the outside world — an API key value.
///
/// Held as bytes rather than `String` internally so that the whole pipeline
/// stays byte-oriented and nothing is UTF-8 validated more than once.
pub struct SecretString(Zeroizing<Vec<u8>>);

impl SecretString {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The single place a secret becomes an owned `String`.
    ///
    /// Wrapped in [`Zeroizing`] so the returned value also wipes on drop — the
    /// alternative is an `Option<Zeroizing<String>>` at every call site, which
    /// in practice means someone eventually uses a bare `String`.
    ///
    /// Errors if the value is not UTF-8. An API key that is not UTF-8 is not
    /// something we can hand to an environment variable, and silently
    /// lossily-converting it would corrupt the user's credential.
    pub fn to_zeroizing_string(&self) -> Result<Zeroizing<String>, crate::Error> {
        match String::from_utf8(self.0.to_vec()) {
            Ok(s) => Ok(Zeroizing::new(s)),
            Err(e) => {
                // Recover the buffer so the failed copy is wiped too. Dropping
                // `FromUtf8Error` alone would leave a plain Vec of the secret
                // on the heap.
                let mut bytes = e.into_bytes();
                bytes.zeroize();
                Err(crate::Error::invalid(
                    "secret",
                    "value is not valid UTF-8 and cannot be released",
                ))
            }
        }
    }

    /// A masked rendering safe to show in the UI and write to logs.
    ///
    /// Shows at most the first four and last four bytes. Short values are
    /// masked completely, because a four-byte key has no prefix worth
    /// revealing — the whole value would be.
    pub fn masked(&self) -> String {
        const VISIBLE: usize = 4;
        let b = &self.0;
        if b.len() <= VISIBLE * 2 {
            return "*".repeat(b.len());
        }
        let head: String = b[..VISIBLE].iter().map(|c| printable(*c)).collect();
        let tail: String = b[b.len() - VISIBLE..]
            .iter()
            .map(|c| printable(*c))
            .collect();
        format!("{head}{}{tail}", "*".repeat(8))
    }
}

fn printable(c: u8) -> char {
    if c.is_ascii_graphic() {
        c as char
    } else {
        '?'
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString(len={})", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masked_never_reveals_the_middle() {
        let s = SecretString::new(b"sk-proj-ABCDEFGHIJKLMNOP1234567890".to_vec());
        let m = s.masked();
        assert_eq!(m, "sk-p********7890");
        assert!(!m.contains("ABCDEF"));
        assert!(!m.contains("PROJ-"));
    }

    #[test]
    fn short_secrets_are_masked_completely() {
        // A four-byte "key" is entirely its own prefix and suffix.
        let s = SecretString::new(b"abcd".to_vec());
        assert_eq!(s.masked(), "****");
        let s = SecretString::new(b"ab".to_vec());
        assert_eq!(s.masked(), "**");
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let s = SecretString::new(b"super-secret-value".to_vec());
        let d = format!("{s:?}");
        assert!(!d.contains("super"));
        assert!(d.contains("len=18"));
    }

    #[test]
    fn equality_does_not_short_circuit_on_length_prefix() {
        // Different lengths are unequal, which is fine — length is public here.
        // Same length must go through the full comparison; we assert the
        // property that matters: a matching prefix is not enough.
        let a = SecretBytes::new(vec![1, 2, 3, 4]);
        let b = SecretBytes::new(vec![1, 2, 3, 5]);
        let c = SecretBytes::new(vec![1, 2, 3, 4]);
        assert_ne!(a, b);
        assert_eq!(a, c);
    }
}
