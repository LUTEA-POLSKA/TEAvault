//! TEAvault security core.
//!
//! This crate is the authoritative security instance. Nothing outside it —
//! not the React UI, not the CLI, not a pipe client — is permitted to perform
//! or skip a security check. Everything that touches key material funnels
//! through here.

pub mod audit;
pub mod backup;
pub mod clipboard;
pub mod crypto;
pub mod error;
pub mod ipc;
pub mod model;
pub mod paths;
pub mod session;
pub mod settings;
pub mod storage;
pub mod vault;

pub use error::{Error, Result};
pub use vault::Vault;

/// Bumped when the on-disk or IPC contract changes in a way that older
/// builds cannot read. Kept separate from the crate version so a patch release
/// that only touches UI cannot claim to be storage-compatible.
pub const PROTOCOL_VERSION: u32 = 1;
