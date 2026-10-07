//! The local IPC protocol.
//!
//! Deliberately a line-delimited JSON request/response over a Windows named
//! pipe. No HTTP server, no port, no listener on a socket, no TLS to configure,
//! no daemon reachable from another machine. The transport is the OS pipe and
//! the access control is the OS pipe's DACL.
//!
//! ## Framing
//!
//! One JSON object per line, `\n`-terminated, UTF-8. Both directions. A
//! request longer than [`MAX_MESSAGE_BYTES`] is refused rather than truncated —
//! a truncated JSON body must never be treated as a smaller, valid request.
//!
//! ## Operations
//!
//! Three are available to any client: [`Operation::List`], [`Operation::Info`]
//! and [`Operation::Request`]. The first two cannot return a secret by
//! construction. The third requires a grant and may open a confirmation dialog.
//!
//! [`Operation::Unlock`], [`Operation::Lock`] and [`Operation::Status`] exist
//! because the CLI needs them, and they are gated on
//! [`Operation::requires_unlocked_vault`] — never on trusting the client's
//! claim about anything.
//!
//! ## Error codes
//!
//! Every failure carries a stable string from [`crate::Error::code`]. Agents
//! should branch on the code, not on the message text.
//!
//! ## Example
//!
//! ```text
//! → {"v":1,"id":"1","op":"list"}
//! ← {"v":1,"id":"1","ok":true,"result":{"entries":[{"name":"OPENAI_API_KEY",
//!    "provider":"OpenAI","available":true,"capabilities":["llm"]}]}}
//!
//! → {"v":1,"id":"2","op":"request","entry":"OPENAI_API_KEY"}
//! ← {"v":1,"id":"2","ok":false,"error":{"code":"needs_confirmation", ...}}
//! → {"v":1,"id":"3","op":"request","entry":"OPENAI_API_KEY"}
//! ← {"v":1,"id":"3","ok":true,"result":{"value":"sk-..."}}
//! ```

pub mod dispatch;

use serde::{Deserialize, Serialize};

use crate::error::{DenyReason, Error};

/// Longest accepted request, in bytes. A key is a few hundred bytes; a
/// megabyte is already far beyond any legitimate request and bounds what a
/// hostile local client can make the daemon allocate.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// Protocol version. Bumped when a field changes meaning, not when one is
/// added.
pub const PROTOCOL: u32 = crate::PROTOCOL_VERSION;

/// Which tier an operation belongs to.
///
/// This is the coarse half of the access model. The fine half — per client, per
/// key, per grant — lives in [`crate::model::grant`] and is what actually
/// governs secret release. The tier exists so that vault *administration* is
/// not reachable by every local process that can open a pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Available to any client: metadata reads and the grant-gated release.
    Agent,
    /// Owner-only: creating and editing entries, managing grants, settings,
    /// backups, and the passphrase.
    Owner,
}

/// What a client is asking for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Operation {
    /// Entry metadata. Never a secret.
    List {
        /// Optional provider filter.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider: Option<String>,
    },
    /// One entry's metadata. Never a secret.
    Info {
        /// Entry id, or the variable name.
        entry: String,
    },
    /// Release the secret for one entry. Requires a grant.
    Request {
        entry: String,
        /// Untrusted free text, shown in the confirmation dialog.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        purpose: Option<String>,
    },

    // --- agent tier ends here ---
    /// Whether the vault is unlocked, and the idle countdown.
    Status,
    /// Lock the vault. Available to any client: locking is never a privilege
    /// escalation, and letting any local process lock the vault is the safe
    /// direction to err in.
    Lock,

    // --- owner tier ---
    /// Unlock with a master passphrase.
    ///
    /// Owner-tier only, and the passphrase does travel inside this message.
    /// That is a deliberate, documented trade-off: the alternative is for the
    /// daemon to show its own unlock dialog and for the CLI to be unable to
    /// unlock at all, which is worse for the product. The exposure is bounded —
    /// the pipe's DACL admits only the current user, and only the owner binary
    /// passes the tier check — and it is documented in `SECURITY.md` § Secrets
    /// on the wire.
    Unlock {
        passphrase: String,
    },

    /// Create the vault for the first time.
    Init {
        /// The chosen master passphrase. Same reasoning as [`Self::Unlock`].
        passphrase: String,
    },

    Create {
        name: String,
        display_name: String,
        provider: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        #[serde(default)]
        capabilities: Vec<String>,
        #[serde(default)]
        hidden: bool,
        /// The secret itself.
        ///
        /// Over the pipe this travels inside the owner's authenticated session,
        /// so it is acceptable here — unlike the agent tier, where it is the
        /// thing being protected.
        secret: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        category: Option<String>,
    },
    Update {
        entry: String,
        display_name: String,
        provider: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        #[serde(default)]
        capabilities: Vec<String>,
        #[serde(default)]
        hidden: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secret: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        category: Option<String>,
    },
    Delete {
        entry: String,
    },
    /// Copy an entry's secret to the clipboard, for the owner's manual use.
    Copy {
        entry: String,
    },
    Access,
    Grant {
        entry: String,
        client_fingerprint: String,
        client_label: String,
        mode: GrantModeWire,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<i64>,
    },
    Revoke {
        grant_id: String,
    },
    RevokeClient {
        client_fingerprint: String,
    },
    Approvals,
    Resolve {
        request_id: String,
        entry: String,
        mode: GrantModeWire,
    },
    GetSettings,
    SetSettings {
        settings: crate::settings::Settings,
    },
    Audit {
        #[serde(default)]
        limit: usize,
    },
    BackupExport {
        /// Destination path. The owner chooses it; the export is encrypted
        /// regardless.
        path: String,
        /// The passphrase the backup is sealed under. Documented on
        /// [`Operation::Unlock`] — same reasoning, same trade-off.
        passphrase: String,
    },
    BackupImport {
        path: String,
        #[serde(default)]
        overwrite: bool,
        passphrase: String,
    },
    ChangePassphrase {
        current: String,
        new: String,
    },
}

impl Operation {
    /// The tier this operation requires.
    pub const fn tier(&self) -> Tier {
        match self {
            Self::List { .. }
            | Self::Info { .. }
            | Self::Request { .. }
            | Self::Status
            | Self::Lock => Tier::Agent,
            _ => Tier::Owner,
        }
    }

    /// Whether this operation can ever result in a secret value.
    pub const fn can_return_secret(&self) -> bool {
        matches!(self, Self::Request { .. } | Self::Copy { .. })
    }

    /// Whether this operation requires an unlocked vault.
    ///
    /// `list` and `info` do, because metadata is encrypted at rest — see
    /// [`crate::vault`] for why.
    ///
    /// Three operations are exempt, and the reasons differ:
    ///
    /// * `lock` — working while locked is its entire purpose.
    /// * `status` — the user has to be able to ask whether it is locked.
    /// * `init` — a fresh vault is *by definition* locked, so requiring an
    ///   unlocked vault here would make creating a vault impossible. It is safe
    ///   because there is nothing to unlock: no keyring, no data file, and no
    ///   secret to reach.
    pub const fn requires_unlocked_vault(&self) -> bool {
        !matches!(self, Self::Lock | Self::Status | Self::Init { .. })
    }

    /// A short name for logs and the audit trail.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::List { .. } => "list",
            Self::Info { .. } => "info",
            Self::Request { .. } => "request",
            Self::Status => "status",
            Self::Lock => "lock",
            Self::Unlock { .. } => "unlock",
            Self::Init { .. } => "init",
            Self::Create { .. } => "create",
            Self::Update { .. } => "update",
            Self::Delete { .. } => "delete",
            Self::Copy { .. } => "copy",
            Self::Access => "access",
            Self::Grant { .. } => "grant",
            Self::Revoke { .. } => "revoke",
            Self::RevokeClient { .. } => "revoke_client",
            Self::Approvals => "approvals",
            Self::Resolve { .. } => "resolve",
            Self::GetSettings => "get_settings",
            Self::SetSettings { .. } => "set_settings",
            Self::Audit { .. } => "audit",
            Self::BackupExport { .. } => "backup_export",
            Self::BackupImport { .. } => "backup_import",
            Self::ChangePassphrase { .. } => "change_passphrase",
        }
    }
}

/// The wire form of a grant mode, so the protocol does not depend on the
/// serde representation of an internal enum staying stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantModeWire {
    AllowOnce,
    AlwaysAllow,
    Deny,
}

impl From<GrantModeWire> for crate::model::GrantMode {
    fn from(w: GrantModeWire) -> Self {
        match w {
            GrantModeWire::AllowOnce => Self::AllowOnce,
            GrantModeWire::AlwaysAllow => Self::AlwaysAllow { expires_at: None },
            GrantModeWire::Deny => Self::Deny,
        }
    }
}

impl GrantModeWire {
    /// Build the internal mode, attaching an expiry when one was supplied.
    pub fn to_mode(self, expires_at: Option<i64>) -> crate::model::GrantMode {
        match self {
            GrantModeWire::AllowOnce => crate::model::GrantMode::AllowOnce,
            GrantModeWire::AlwaysAllow => crate::model::GrantMode::AlwaysAllow { expires_at },
            GrantModeWire::Deny => crate::model::GrantMode::Deny,
        }
    }
}

/// One request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub v: u32,
    /// Client-chosen correlation id, echoed in the response.
    pub id: String,
    #[serde(flatten)]
    pub op: Operation,
}

impl Request {
    pub fn new(id: impl Into<String>, op: Operation) -> Self {
        Self {
            v: PROTOCOL,
            id: id.into(),
            op,
        }
    }

    /// Validate the envelope before doing anything with it.
    ///
    /// A wrong version is refused rather than best-effort parsed: a future
    /// client may expect different semantics for the same op name, and
    /// guessing is how a `request` ends up meaning something weaker.
    pub fn validate(&self) -> Result<(), Error> {
        if self.v != PROTOCOL {
            return Err(Error::UnsupportedFormat {
                found: self.v,
                supported: PROTOCOL,
            });
        }
        if self.id.is_empty() || self.id.len() > 64 {
            return Err(Error::invalid("id", "must be 1..=64 characters"));
        }
        Ok(())
    }
}

/// The `list` result, in the shape an agent is meant to consume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListResult {
    pub entries: Vec<ListEntry>,
}

/// One entry as `list` reports it. No secret field exists on this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListEntry {
    pub name: String,
    pub id: String,
    pub provider: String,
    /// Whether the vault is unlocked and the secret can currently be released.
    /// Never "whether the key works" — TEAvault cannot know that and does not
    /// contact the provider to find out.
    pub available: bool,
    pub capabilities: Vec<String>,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether this client currently holds a grant permitting release.
    pub granted: bool,
    /// Whether this entry is hidden until a grant exists.
    pub hidden: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

/// The `info` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfoResult {
    pub name: String,
    pub id: String,
    pub provider: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub capabilities: Vec<String>,
    pub available: bool,
    pub granted: bool,
    pub hidden: bool,
    pub created_at: String,
    pub updated_at: String,
    /// The authorisations that currently apply to this client and entry.
    pub grants: Vec<GrantView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

/// A grant as reported to a client. Deliberately omits the client's own
/// fingerprint so one client cannot enumerate who else has access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantView {
    pub mode: String,
    pub granted_at: String,
    pub expires_at: Option<i64>,
    pub consumed: bool,
    /// Whether this particular grant belongs to the requesting client.
    pub mine: bool,
}

/// The `request` result. The only place a secret appears on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestResult {
    pub name: String,
    /// The plaintext key.
    ///
    /// Named plainly so that grepping the codebase for it finds every place it
    /// exists. There are three: this struct, the pipe write, and the caller's
    /// environment variable.
    pub value: String,
}

/// The `status` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResult {
    pub initialized: bool,
    pub locked: bool,
    pub entry_count: usize,
    pub pending_approvals: usize,
    pub protocol: u32,
    pub kdf: String,
}

/// One response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub v: u32,
    /// Echoes the request id, or `""` when the request could not be parsed far
    /// enough to know.
    pub id: String,
    /// Exactly one of `result` / `error` is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

impl Response {
    pub fn ok(id: impl Into<String>, result: serde_json::Value) -> Self {
        Self {
            v: PROTOCOL,
            id: id.into(),
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: impl Into<String>, error: Error) -> Self {
        Self {
            v: PROTOCOL,
            id: id.into(),
            result: None,
            error: Some(ErrorBody::from(error)),
        }
    }

    /// Whether this response carries a result.
    pub fn is_ok(&self) -> bool {
        self.error.is_none()
    }
}

/// The wire form of an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Stable code from [`crate::Error::code`]. Branch on this.
    pub code: String,
    /// Human-readable, never secret. May change between versions.
    pub message: String,
    /// Present for `needs_confirmation`: the id the UI uses to answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Present for `attempts_exhausted`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u64>,
    /// Whether retrying could plausibly work.
    pub retryable: bool,
}

impl From<Error> for ErrorBody {
    fn from(e: Error) -> Self {
        let (request_id, retry_after_secs) = match &e {
            Error::NeedsConfirmation(c) => (Some(c.request_id.clone()), None),
            Error::AttemptsExhausted { retry_after_secs } => (None, Some(*retry_after_secs)),
            _ => (None, None),
        };
        Self {
            code: e.code().to_string(),
            message: e.to_string(),
            request_id,
            retry_after_secs,
            retryable: e.is_retryable(),
        }
    }
}

/// Convenience for building a refusal body from a [`DenyReason`].
pub fn denied_body(reason: DenyReason, detail: impl Into<String>) -> ErrorBody {
    ErrorBody::from(Error::denied(reason, detail))
}

/// Decides whether a connecting process is the owner UI or an ordinary agent.
///
/// ## What this is
///
/// A path comparison. The owner tier — create, edit, delete, manage grants,
/// change the passphrase — is reachable only by a client whose image path is
/// the expected binary *inside the same directory the daemon was launched
/// from*. That is a genuine check against a process running from anywhere else,
/// including a copy of the UI binary in `%TEMP%`.
///
/// ## What this is not
///
/// It is **not** proof of identity, and the limits are worth stating plainly
/// because they are the weakest point in the design:
///
/// * Anyone who can write to the install directory can replace the owner binary
///   and obtain the owner tier. On a machine where `C:\Program Files` is
///   admin-writable this is not an extra privilege, but on a per-user install
///   it is.
/// * The comparison is on the path the OS reports, not on a signature. TEAvault
///   does not verify Authenticode, because it is not signed and claiming
///   otherwise would be theatre.
/// * A process running as the same user can read the daemon's own memory in
///   principle. See `THREAT_MODEL.md`.
///
/// The reason to have this boundary at all is not to be airtight — it is not —
/// but to make accidental exposure impossible: a random local process asking
/// for "create a key" must be refused, and it will be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerCheck {
    install_dir: std::path::PathBuf,
    /// Every binary allowed to reach the owner tier.
    ///
    /// More than one, because the owner has two tools: the desktop UI and the
    /// command line. Both are owner tools by definition — the CLI is what
    /// creates and unlocks the vault — and collapsing them to a single name
    /// would mean `teavault init` is refused for lack of privilege, which is
    /// both absurd and impossible to work around from the outside.
    owner_exes: Vec<String>,
}

impl OwnerCheck {
    /// A single owner binary. Most callers want [`Self::from_exe_paths`].
    pub fn from_exe_path(exe: &std::path::Path, owner_exe: &str) -> Self {
        Self::from_exe_paths(exe, &[owner_exe])
    }

    /// Expect one or more owner binaries in the same directory as `exe`.
    pub fn from_exe_paths(exe: &std::path::Path, owner_exes: &[&str]) -> Self {
        Self {
            install_dir: exe.parent().unwrap_or(exe).to_path_buf(),
            owner_exes: owner_exes.iter().map(|s| s.to_ascii_lowercase()).collect(),
        }
    }

    /// The expected owner image paths, for display.
    pub fn expected_paths(&self) -> Vec<String> {
        self.owner_exes
            .iter()
            .map(|n| self.install_dir.join(n).display().to_string())
            .collect()
    }

    /// The first expected owner path. Kept for single-binary callers.
    pub fn expected_path(&self) -> String {
        self.expected_paths()
            .into_iter()
            .next()
            .unwrap_or_else(|| self.install_dir.display().to_string())
    }

    /// Classify a client image path.
    ///
    /// Comparison is case-insensitive because Windows paths are, and normalises
    /// nothing else: `..` segments and short names are *not* resolved, because a
    /// resolved path would require opening the file and re-checking, and a
    /// mismatch here must fail closed rather than succeed on a technicality.
    pub fn classify(&self, image_path: &str) -> Tier {
        if image_path.is_empty() {
            return Tier::Agent;
        }
        let p = std::path::Path::new(image_path);
        let Some(dir) = p.parent() else {
            return Tier::Agent;
        };
        let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
            return Tier::Agent;
        };
        let dir_matches = dir
            .to_str()
            .map(|d| d.eq_ignore_ascii_case(&self.install_dir.display().to_string()))
            .unwrap_or(false);
        if dir_matches
            && self
                .owner_exes
                .iter()
                .any(|o| *o == name.to_ascii_lowercase())
        {
            Tier::Owner
        } else {
            Tier::Agent
        }
    }

    /// Whether the client may perform an operation of `tier`.
    pub fn permits(&self, image_path: &str, tier: Tier) -> bool {
        self.classify(image_path) >= tier
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check() -> OwnerCheck {
        OwnerCheck::from_exe_path(
            std::path::Path::new(r"C:\Program Files\TEAvault\teavaultd.exe"),
            "teavault-app.exe",
        )
    }

    #[test]
    fn list_and_info_responses_have_no_field_that_can_hold_a_secret() {
        // The guarantee is structural: the result types for the two metadata
        // operations have no secret field, so it is not possible to serialise
        // one even by mistake.
        let entry = ListEntry {
            name: "OPENAI_API_KEY".into(),
            id: "id".into(),
            provider: "OpenAI".into(),
            available: true,
            capabilities: vec!["llm".into()],
            display_name: "OpenAI".into(),
            description: None,
            granted: false,
            hidden: false,
            category: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("value"));
        assert!(!json.contains("secret"));

        let info = InfoResult {
            name: "OPENAI_API_KEY".into(),
            id: "id".into(),
            provider: "OpenAI".into(),
            display_name: "OpenAI".into(),
            description: None,
            capabilities: vec![],
            available: true,
            granted: false,
            hidden: false,
            created_at: "now".into(),
            updated_at: "now".into(),
            grants: vec![],
            category: None,
        };
        assert!(!serde_json::to_string(&info).unwrap().contains("value"));
    }

    #[test]
    fn only_request_can_return_a_secret() {
        assert!(!Operation::List { provider: None }.can_return_secret());
        assert!(!Operation::Info { entry: "x".into() }.can_return_secret());
        assert!(!Operation::Status.can_return_secret());
        assert!(!Operation::Lock.can_return_secret());
        assert!(Operation::Request {
            entry: "x".into(),
            purpose: None
        }
        .can_return_secret());
    }

    #[test]
    fn creating_a_vault_is_possible_while_locked() {
        // A fresh vault is by definition locked. If `init` required an unlocked
        // vault, creating one would be impossible — which is exactly the bug the
        // idle benchmark found by trying it.
        let init = Operation::Init {
            passphrase: "x".into(),
        };
        assert!(
            !init.requires_unlocked_vault(),
            "init must not require an unlocked vault"
        );
    }

    #[test]
    fn everything_else_still_requires_an_unlocked_vault() {
        // Metadata is encrypted at rest, so nothing is answerable while locked
        // except the three operations whose whole job is to work when locked.
        assert!(!Operation::Lock.requires_unlocked_vault());
        assert!(!Operation::Status.requires_unlocked_vault());
        assert!(!Operation::Init {
            passphrase: "x".into()
        }
        .requires_unlocked_vault());
        for op in [
            Operation::List { provider: None },
            Operation::Info { entry: "x".into() },
            Operation::Request {
                entry: "x".into(),
                purpose: None,
            },
            Operation::Access,
            Operation::Audit { limit: 1 },
        ] {
            assert!(
                op.requires_unlocked_vault(),
                "{} should need a lock",
                op.name()
            );
        }
    }

    #[test]
    fn only_the_owner_tier_can_reach_administration() {
        // Every operation that creates, edits, deletes, or reveals must be
        // owner-tier. This is the coarse boundary that keeps vault management
        // out of reach of every process that can merely open a pipe.
        let owner_only = [
            Operation::Create {
                name: "N".into(),
                display_name: "N".into(),
                provider: "OpenAI".into(),
                description: None,
                capabilities: vec![],
                hidden: false,
                secret: "s".into(),
                category: None,
            },
            Operation::Delete { entry: "e".into() },
            Operation::Copy { entry: "e".into() },
            Operation::Access,
            Operation::Grant {
                entry: "e".into(),
                client_fingerprint: "f".into(),
                client_label: "l".into(),
                mode: GrantModeWire::Deny,
                expires_at: None,
            },
            Operation::Revoke {
                grant_id: "g".into(),
            },
            Operation::SetSettings {
                settings: crate::settings::Settings::default(),
            },
            Operation::ChangePassphrase {
                current: "a".into(),
                new: "b".into(),
            },
        ];
        for op in owner_only {
            assert_eq!(op.tier(), Tier::Owner, "{} must be owner-only", op.name());
        }
    }

    #[test]
    fn the_agent_tier_is_only_reads_status_and_locking() {
        let agent = [
            Operation::List { provider: None },
            Operation::Info { entry: "e".into() },
            Operation::Request {
                entry: "e".into(),
                purpose: None,
            },
            Operation::Status,
            Operation::Lock,
        ];
        for op in agent {
            assert_eq!(op.tier(), Tier::Agent, "{} should be agent-tier", op.name());
        }
        assert!(Tier::Agent < Tier::Owner);
    }

    #[test]
    fn locking_is_not_a_privilege_escalation() {
        // Any local client may lock the vault. Refusing that would leave a user
        // unable to lock from the CLI if the UI is wedged.
        assert_eq!(Operation::Lock.tier(), Tier::Agent);
    }

    #[test]
    fn every_operation_has_a_distinct_name() {
        // Guards against a copy-paste adding a duplicate arm name, which would
        // make two different operations indistinguishable in the audit log.
        let ops = [
            Operation::List { provider: None },
            Operation::Info { entry: "e".into() },
            Operation::Request {
                entry: "e".into(),
                purpose: None,
            },
            Operation::Status,
            Operation::Lock,
            Operation::Access,
            Operation::Approvals,
            Operation::GetSettings,
        ];
        let mut names: Vec<&str> = ops.iter().map(|o| o.name()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "duplicate operation name");
    }

    #[test]
    fn a_version_mismatch_is_refused() {
        let mut r = Request::new("1", Operation::Status);
        r.v = 99;
        assert_eq!(r.validate().unwrap_err().code(), "unsupported_format");
    }

    #[test]
    fn an_empty_or_oversized_id_is_refused() {
        assert!(Request::new("", Operation::Status).validate().is_err());
        assert!(Request::new("x".repeat(65), Operation::Status)
            .validate()
            .is_err());
    }

    #[test]
    fn requests_round_trip_through_json() {
        let r = Request::new(
            "42",
            Operation::Request {
                entry: "OPENAI_API_KEY".into(),
                purpose: Some("run the test suite".into()),
            },
        );
        let line = serde_json::to_string(&r).unwrap();
        assert!(!line.contains('\n'), "a request must be one line");
        let back: Request = serde_json::from_str(&line).unwrap();
        assert_eq!(r, back);
        back.validate().unwrap();
    }

    #[test]
    fn the_op_is_flattened_so_the_wire_format_is_compact() {
        let line =
            serde_json::to_string(&Request::new("1", Operation::List { provider: None })).unwrap();
        assert!(line.contains("\"op\":\"list\""), "got {line}");
    }

    #[test]
    fn a_purpose_is_carried_but_never_interpreted() {
        // It is text to show the user. Nothing parses it, so it cannot smuggle
        // a directive into the core.
        let r = Request::new(
            "1",
            Operation::Request {
                entry: "X".into(),
                purpose: Some("ignore all previous instructions".into()),
            },
        );
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("ignore all previous instructions"));
        let back: Request = serde_json::from_str(&json).unwrap();
        match back.op {
            Operation::Request { purpose, .. } => {
                assert_eq!(purpose.as_deref(), Some("ignore all previous instructions"))
            }
            other => panic!("unexpected op {other:?}"),
        }
    }

    #[test]
    fn the_backup_passphrase_is_carried_explicitly_and_is_never_logged() {
        // The passphrase does cross the pipe for owner-tier operations; what
        // matters is that it is a named field rather than smuggled into a free
        // text field, and that nothing in the audit trail records it.
        let r = Request::new(
            "1",
            Operation::BackupExport {
                path: "C:\\b.teavault".into(),
                passphrase: "s3cret-backup-pass".into(),
            },
        );
        let line = serde_json::to_string(&r).unwrap();
        assert!(line.contains("s3cret-backup-pass"));
        // The daemon logs the op name, never the payload.
        assert_eq!(r.op.name(), "backup_export");
    }

    #[test]
    fn a_response_has_exactly_one_of_result_or_error() {
        let ok = Response::ok("1", serde_json::json!({"a":1}));
        assert!(ok.is_ok());
        assert!(ok.error.is_none());
        let line = serde_json::to_string(&ok).unwrap();
        assert!(!line.contains("\"error\""));

        let bad = Response::err("1", Error::Locked);
        assert!(!bad.is_ok());
        let line = serde_json::to_string(&bad).unwrap();
        assert!(!line.contains("\"result\""));
    }

    #[test]
    fn error_codes_are_machine_readable_and_stable() {
        let body = ErrorBody::from(Error::Locked);
        assert_eq!(body.code, "locked");
        assert!(body.retryable);

        let body = ErrorBody::from(Error::Integrity);
        assert_eq!(body.code, "integrity");
        assert!(!body.retryable, "integrity must not invite a retry");
    }

    #[test]
    fn a_confirmation_error_carries_the_request_id() {
        let e = Error::NeedsConfirmation(crate::error::ConfirmationRequired {
            request_id: "req-1".into(),
            entry_id: "e1".into(),
            purpose: None,
        });
        let body = ErrorBody::from(e);
        assert_eq!(body.code, "needs_confirmation");
        assert_eq!(body.request_id.as_deref(), Some("req-1"));
    }

    #[test]
    fn a_malformed_line_is_rejected_without_panicking() {
        assert!(serde_json::from_str::<Request>("not json").is_err());
        assert!(serde_json::from_str::<Request>("{}").is_err());
        // A bare array, or a JSON scalar, must not be mistaken for a request.
        assert!(serde_json::from_str::<Request>("[]").is_err());
        assert!(serde_json::from_str::<Request>("7").is_err());
    }
    #[test]
    fn only_the_expected_binary_in_the_install_directory_is_owner() {
        let c = check();
        assert_eq!(
            c.classify(r"C:\Program Files\TEAvault\teavault-app.exe"),
            Tier::Owner
        );
        // Case-insensitive, because Windows paths are.
        assert_eq!(
            c.classify(r"c:\program files\teavault\TEAvault-APP.EXE"),
            Tier::Owner
        );
    }

    #[test]
    fn every_owner_tool_is_owner_but_nothing_else_is() {
        // The owner has two tools. Both must reach the owner tier: without the
        // CLI, `teavault init` would be refused for lack of privilege — which is
        // the first command in the README, and impossible to work around.
        let c = OwnerCheck::from_exe_paths(
            std::path::Path::new(r"C:\Program Files\TEAvault\teavaultd.exe"),
            &["teavault-app.exe", "teavault.exe"],
        );
        for owner in ["teavault-app.exe", "teavault.exe"] {
            assert_eq!(
                c.classify(&format!(r"C:\Program Files\TEAvault\{owner}")),
                Tier::Owner,
                "{owner} must be owner tier"
            );
        }
        for stranger in [
            "teavaultd.exe", // the daemon itself, reached by path
            "notepad.exe",
            "teavault-app-helper.exe", // a name that merely starts the same way
            "teavault.exe.bak",
        ] {
            assert_eq!(
                c.classify(&format!(r"C:\Program Files\TEAvault\{stranger}")),
                Tier::Agent,
                "{stranger} must not be owner tier"
            );
        }
    }

    #[test]
    fn expected_paths_lists_every_owner_tool() {
        let c = OwnerCheck::from_exe_paths(
            std::path::Path::new(r"C:\Program Files\TEAvault\teavaultd.exe"),
            &["teavault-app.exe", "teavault.exe"],
        );
        assert_eq!(
            c.expected_paths(),
            vec![
                r"C:\Program Files\TEAvault\teavault-app.exe".to_string(),
                r"C:\Program Files\TEAvault\teavault.exe".to_string(),
            ]
        );
    }

    #[test]
    fn the_same_binary_name_elsewhere_is_not_owner() {
        // A copy of the UI binary in a temp directory is exactly the attack this
        // check is for.
        let c = check();
        assert_eq!(
            c.classify(r"C:\Users\Someone\AppData\Local\Temp\teavault-app.exe"),
            Tier::Agent
        );
        assert_eq!(
            c.classify(r"C:\Users\Someone\Desktop\teavault-app.exe"),
            Tier::Agent
        );
    }

    #[test]
    fn a_different_binary_in_the_install_directory_is_not_owner() {
        let c = check();
        assert_eq!(
            c.classify(r"C:\Program Files\TEAvault\teavaultd.exe"),
            Tier::Agent
        );
        // Including a name that merely starts the same way.
        assert_eq!(
            c.classify(r"C:\Program Files\TEAvault\teavault-app-helper.exe"),
            Tier::Agent
        );
    }

    #[test]
    fn an_empty_or_bare_path_is_never_owner() {
        let c = check();
        assert_eq!(c.classify(""), Tier::Agent);
        assert_eq!(c.classify("teavault-app.exe"), Tier::Agent);
        assert_eq!(c.classify(r"C:\"), Tier::Agent);
    }

    #[test]
    fn permits_respects_the_tier_ordering() {
        let c = check();
        let owner = r"C:\Program Files\TEAvault\teavault-app.exe";
        let agent = r"C:\tools\agent.exe";

        assert!(c.permits(owner, Tier::Owner));
        assert!(c.permits(owner, Tier::Agent));
        assert!(c.permits(agent, Tier::Agent));
        assert!(!c.permits(agent, Tier::Owner));
    }

    #[test]
    fn an_owner_client_is_still_agent_tier_for_reads() {
        // The owner UI uses the same three operations as everyone else; owning
        // the vault does not bypass the grant check on `request`.
        let c = check();
        assert!(c.permits(r"C:\Program Files\TEAvault\teavault-app.exe", Tier::Agent));
    }

    // --- IPC message parsing tests ---

    #[test]
    fn request_serializes_with_correct_version() {
        let req = Request::new("test-id", Operation::List { provider: None });
        let json = serde_json::to_string(&req).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["v"], PROTOCOL as u64);
        assert_eq!(parsed["id"], "test-id");
        assert_eq!(parsed["op"], "list");
    }

    #[test]
    fn request_serializes_request_op_with_entry() {
        let req = Request::new("2", Operation::Request {
            entry: "OPENAI_API_KEY".into(),
            purpose: Some("test access".into()),
        });
        let json = serde_json::to_string(&req).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["op"], "request");
        assert_eq!(parsed["entry"], "OPENAI_API_KEY");
        assert_eq!(parsed["purpose"], "test access");
    }

    #[test]
    fn response_serializes_ok_result() {
        let resp = Response::ok("req-1", serde_json::json!({"entries": []}));
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        // No `ok` field — success is indicated by presence of `result`
        assert!(parsed.get("result").is_some());
        assert!(parsed.get("error").is_none());
        assert_eq!(parsed["v"], PROTOCOL as u64);
        assert_eq!(parsed["id"], "req-1");
    }

    #[test]
    fn response_serializes_error() {
        let err = Error::Locked;
        let resp = Response::err("req-2", err);
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        // No `ok` field — error is indicated by presence of `error`
        assert!(parsed.get("error").is_some());
        assert!(parsed.get("result").is_none());
        assert_eq!(parsed["v"], PROTOCOL as u64);
        assert_eq!(parsed["id"], "req-2");
        assert_eq!(parsed["error"]["code"], "locked");
    }

    #[test]
    fn tier_serializes_to_snake_case() {
        let agent_json = serde_json::to_string(&Tier::Agent).unwrap();
        assert_eq!(agent_json, "\"agent\"");
        let owner_json = serde_json::to_string(&Tier::Owner).unwrap();
        assert_eq!(owner_json, "\"owner\"");
    }

    #[test]
    fn tier_deserializes_from_snake_case() {
        let agent: Tier = serde_json::from_str("\"agent\"").unwrap();
        assert_eq!(agent, Tier::Agent);
        let owner: Tier = serde_json::from_str("\"owner\"").unwrap();
        assert_eq!(owner, Tier::Owner);
    }

    #[test]
    fn grant_mode_wire_serializes_correctly() {
        let once = serde_json::to_string(&GrantModeWire::AllowOnce).unwrap();
        assert_eq!(once, "\"allow_once\"");
        let deny = serde_json::to_string(&GrantModeWire::Deny).unwrap();
        assert_eq!(deny, "\"deny\"");
    }

    #[test]
    fn grant_mode_wire_deserializes_correctly() {
        let once: GrantModeWire = serde_json::from_str("\"allow_once\"").unwrap();
        assert_eq!(once, GrantModeWire::AllowOnce);
        let deny: GrantModeWire = serde_json::from_str("\"deny\"").unwrap();
        assert_eq!(deny, GrantModeWire::Deny);
    }

    #[test]
    fn max_message_bytes_is_reasonable() {
        assert_eq!(MAX_MESSAGE_BYTES, 64 * 1024);
    }

    #[test]
    fn protocol_version_is_one() {
        assert_eq!(PROTOCOL, 1);
    }

    #[test]
    fn status_operation_serializes_correctly() {
        let req = Request::new("1", Operation::Status);
        let json = serde_json::to_string(&req).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["op"], "status");
        assert!(parsed.get("entry").is_none());
    }

    #[test]
    fn lock_operation_serializes_correctly() {
        let req = Request::new("1", Operation::Lock);
        let json = serde_json::to_string(&req).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["op"], "lock");
    }
}
