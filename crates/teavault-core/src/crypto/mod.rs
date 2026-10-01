//! Cryptography.
//!
//! Everything in this module is either a well-maintained upstream primitive —
//! AES-256-GCM, Argon2id, SHA-256, HMAC — or the wiring between them. There is
//! no hand-rolled cipher, no custom padding, no bespoke key schedule and no
//! "we only need a little obfuscation" shortcut anywhere in TEAvault.
//!
//! | concern | primitive | module |
//! |---|---|---|
//! | passphrase → key | Argon2id, OWASP parameters | [`kdf`] |
//! | record encryption | AES-256-GCM, random 96-bit nonce | [`aead`] |
//! | key at rest | data key wrapped under the derived KEK | [`keyring`] |
//! | memory hygiene | `zeroize`-backed containers | [`secret`] |
//!
//! See `SECURITY.md` for the threat model these choices answer, and for the
//! limits of the memory hygiene claims.

pub mod aead;
pub mod hex;
pub mod kdf;
pub mod keyring;
pub mod secret;

pub use aead::{Sealed, KEY_LEN, NONCE_LEN, TAG_LEN};
pub use kdf::KdfParams;
pub use keyring::Keyring;
pub use secret::{SecretBytes, SecretString};
