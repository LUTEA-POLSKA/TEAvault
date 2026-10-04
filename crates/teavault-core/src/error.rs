//! The crate's error type.
//!
//! Two rules govern everything here:
//!
//! 1. **No variant carries secret material.** No passphrase, no plaintext key,
//!    no request body, no partial ciphertext interpreted as data. An error is
//!    safe to serialise, log, put in a `Result` on an IPC boundary, and show in
//!    a dialog.
//! 2. **Every failure is a refusal.** There is no `Err` variant from which a
//!    caller can recover by falling back to plaintext, by skipping a check, or
//!    by retrying with weaker parameters. A caller that receives an error has
//!    received a decision, not a hiccup.

use std::fmt;

/// Why a secret request was refused. Distinguishes "you have not been granted
/// this" from "you have, but not right now", because the remediation differs
/// and conflating them trains users to retry blindly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// The client has no grant covering this key.
    NoGrant,
    /// A grant exists but its validity window has passed.
    Expired,
    /// A standing deny was recorded for this client and key.
    DeniedByUser,
    /// The vault is locked, so no key may be released regardless of grants.
    VaultLocked,
    /// The client is not permitted to use this operation at all.
    OperationNotAllowed,
    /// The request was malformed or attempted to tamper with state.
    InvalidRequest,
}

impl DenyReason {
    /// Stable machine-readable code, shared by IPC, CLI and the UI.
    pub const fn code(self) -> &'static str {
        match self {
            Self::NoGrant => "no_grant",
            Self::Expired => "grant_expired",
            Self::DeniedByUser => "denied_by_user",
            Self::VaultLocked => "vault_locked",
            Self::OperationNotAllowed => "operation_not_allowed",
            Self::InvalidRequest => "invalid_request",
        }
    }
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::NoGrant => "no grant covers this key for this client",
            Self::Expired => "the grant for this key has expired",
            Self::DeniedByUser => "access was denied for this client and key",
            Self::VaultLocked => "the vault is locked",
            Self::OperationNotAllowed => "this client may not perform this operation",
            Self::InvalidRequest => "the request was rejected as malformed",
        };
        f.write_str(s)
    }
}

/// A refusal that needs a human decision before it can be retried.
///
/// Carried as its own variant rather than folded into [`DenyReason`] because
/// the daemon must be able to distinguish "deny and log it" from "wake the UI
/// and wait for the user".
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConfirmationRequired {
    /// Opaque handle the UI uses to answer this specific request.
    pub request_id: String,
    /// Entry the client asked for. Metadata only — never the secret.
    pub entry_id: String,
    /// What the client claims it wants the key for. Untrusted free text.
    pub purpose: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No vault exists at the configured location yet.
    #[error("no vault exists yet — run `teavault init` first")]
    NotInitialized,

    /// A vault already exists; refusing to clobber one.
    #[error("a vault already exists — refusing to overwrite it")]
    AlreadyInitialized,

    /// The vault is locked. The single most common refusal.
    #[error("the vault is locked")]
    Locked,

    /// The supplied passphrase did not unwrap the data key.
    ///
    /// Deliberately indistinguishable from a corrupted keyring: telling a
    /// caller "wrong passphrase" versus "damaged file" tells an offline
    /// attacker which one they are looking at, and there is no recovery action
    /// that differs for the legitimate user either.
    #[error("the master passphrase is incorrect, or the keyring is damaged")]
    InvalidPassphrase,

    /// Too many failed unlock attempts in a row.
    #[error("too many failed unlock attempts — locked out until {retry_after_secs}s")]
    AttemptsExhausted { retry_after_secs: u64 },

    /// AEAD authentication failed, or the file failed its integrity check.
    ///
    /// This is always a hard stop. There is no fallback path.
    #[error("integrity check failed — the data was modified or is damaged")]
    Integrity,

    /// On-disk format is not one this build understands.
    #[error("unsupported format version {found} (this build understands up to {supported})")]
    UnsupportedFormat { found: u32, supported: u32 },

    /// The named object does not exist.
    #[error("{kind} not found: {name}")]
    NotFound { kind: &'static str, name: String },

    /// A value failed validation before it was allowed near the crypto layer.
    #[error("invalid {field}: {reason}")]
    Invalid { field: &'static str, reason: String },

    /// Security-relevant refusal with a machine-readable cause.
    ///
    /// The detail is part of the message on purpose. It is documented as "free
    /// text for the audit log and the UI", and an error that reaches the user as
    /// "access denied: no grant" without saying *which* grant, or *why this
    /// particular* request is refused, is not a usable explanation — it looks like
    /// a bug. Branch on the `code`; read the message.
    #[error("access denied: {reason}: {detail}")]
    Denied {
        reason: DenyReason,
        /// Free-text detail for the audit log and the UI. Never secret.
        detail: String,
    },

    /// Needs an interactive decision from the vault owner.
    #[error("this request needs the vault owner's approval")]
    NeedsConfirmation(ConfirmationRequired),

    /// Filesystem failure. Paths only; never file contents.
    #[error("{context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: std::io::Error,
    },

    /// Serialisation failure of our own data — indicates a bug or damage.
    #[error("stored data is malformed: {0}")]
    Malformed(String),
}

impl Error {
    /// Convenience constructor for the common refusal.
    pub fn denied(reason: DenyReason, detail: impl Into<String>) -> Self {
        Self::Denied {
            reason,
            detail: detail.into(),
        }
    }

    pub fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        Self::Invalid {
            field,
            reason: reason.into(),
        }
    }

    pub fn not_found(kind: &'static str, name: impl Into<String>) -> Self {
        Self::NotFound {
            kind,
            name: name.into(),
        }
    }

    pub fn io(context: &'static str, source: std::io::Error) -> Self {
        Self::Io { context, source }
    }

    /// Stable machine-readable code, used verbatim by the IPC protocol, the CLI
    /// exit mapping and the UI. Adding a variant forces adding a code here,
    /// because the match is exhaustive.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotInitialized => "not_initialized",
            Self::AlreadyInitialized => "already_initialized",
            Self::Locked => "locked",
            Self::InvalidPassphrase => "invalid_passphrase",
            Self::AttemptsExhausted { .. } => "attempts_exhausted",
            Self::Integrity => "integrity",
            Self::UnsupportedFormat { .. } => "unsupported_format",
            Self::NotFound { .. } => "not_found",
            Self::Invalid { .. } => "invalid",
            Self::Denied { reason, .. } => reason.code(),
            Self::NeedsConfirmation(_) => "needs_confirmation",
            Self::Io { .. } => "io",
            Self::Malformed(_) => "malformed",
        }
    }

    /// Whether retrying the identical request could plausibly succeed.
    ///
    /// The UI uses this to decide between "try again" and "this is final", and
    /// the CLI uses it for its exit code.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Io { .. } | Self::Locked | Self::NeedsConfirmation(_)
        )
    }

    /// Whether this is a security refusal rather than a fault. Drives the
    /// "security errors fail closed" rule: these are always surfaced, never
    /// swallowed by a retry loop.
    pub fn is_security_refusal(&self) -> bool {
        matches!(
            self,
            Self::Locked
                | Self::InvalidPassphrase
                | Self::AttemptsExhausted { .. }
                | Self::Integrity
                | Self::Denied { .. }
                | Self::NeedsConfirmation(_)
        )
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Serialisation failures are always our own data being malformed, whether
/// that means a damaged file or a bug. Never surfaces the serialised bytes,
/// which could be key material.
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        // `classify` deliberately has no Display impl, which is exactly right
        // for us: the message could contain a fragment of the input. The kind
        // is enough to act on.
        Self::Malformed(format!("json ({:?})", e.classify()))
    }
}

/// The OS random source failing is a hard integrity problem, not a transient
/// fault — every key and nonce depends on it.
impl From<getrandom::Error> for Error {
    fn from(_: getrandom::Error) -> Self {
        Self::Integrity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_security_refusal_is_not_retryable_merely_because_it_is_a_refusal() {
        // `Locked` is deliberately retryable — unlocking is the remedy. These
        // are the ones where retrying cannot change the answer, and letting a
        // caller retry them would only hand it a second attempt at whatever it
        // is probing.
        let security = [
            Error::InvalidPassphrase,
            Error::AttemptsExhausted {
                retry_after_secs: 60,
            },
            Error::Integrity,
            Error::denied(DenyReason::NoGrant, "x"),
            Error::denied(DenyReason::DeniedByUser, "x"),
        ];
        for e in security {
            assert!(e.is_security_refusal(), "{} was not a refusal", e.code());
            assert!(!e.is_retryable(), "{} must not look retryable", e.code());
        }
    }

    #[test]
    fn locked_is_retryable_because_unlocking_is_the_remedy() {
        assert!(Error::Locked.is_retryable());
    }

    #[test]
    fn codes_are_unique_per_variant() {
        let codes = [
            Error::NotInitialized.code(),
            Error::AlreadyInitialized.code(),
            Error::Locked.code(),
            Error::InvalidPassphrase.code(),
            Error::Integrity.code(),
            Error::UnsupportedFormat {
                found: 9,
                supported: 1,
            }
            .code(),
            Error::not_found("entry", "A").code(),
            Error::invalid("name", "empty").code(),
            Error::io("open", std::io::Error::other("x")).code(),
            Error::Malformed("x".into()).code(),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for c in codes {
            assert!(seen.insert(c), "duplicate code {c}");
        }
    }
}
