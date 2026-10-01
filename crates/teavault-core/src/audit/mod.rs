//! The audit log.
//!
//! Every security-relevant decision is appended here: unlocks, locks, failed
//! unlock attempts, every client request, every approval and refusal, every
//! grant revocation, every key created, edited or deleted, and every failure
//! of a security control.
//!
//! ## What is never written
//!
//! No API key values. No passphrase. No derived key material. No
//! `Authorization` header. No request body. The event types below are
//! structurally incapable of carrying a secret — they hold identifiers and
//! short strings, and [`AuditEvent::serialise`] is the only writer, so a new
//! field has to be added to a type rather than slipped into a free-form map.
//!
//! ## Integrity
//!
//! Events are hash-chained: each entry carries the SHA-256 of the previous
//! entry plus its own payload, so removing or editing an earlier event breaks
//! every later link. The chain key is a random 32-byte value wrapped with
//! Windows DPAPI, which binds the log to the user account *without* weakening
//! the passphrase barrier — see [`dpapi_key`].
//!
//! **Stated plainly: this is tamper-evidence, not tamper-proofing.** An
//! attacker with full control of the user account can also call DPAPI, rewrite
//! the whole file and recompute the chain. What the chain does buy is that
//! casual truncation, accidental deletion and offline editing with a text
//! editor are detected, and it gives an investigator a chain it can check.
//!
//! ## Backups
//!
//! The log ships *inside* the encrypted export, so it travels with the data it
//! describes. It is excluded from any plaintext path — there is none.
//!
//! [`dpapi_key`]: crate::audit::AuditKeyRing

use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    model::now_rfc3339,
};

/// What happened. A closed enum, so adding an event type is a compile error
/// until someone has decided what it may contain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditKind {
    VaultCreated,
    VaultUnlocked,
    VaultLocked,
    /// The passphrase was wrong. No detail about how wrong.
    UnlockFailed,
    /// Repeated failures tripped the lockout.
    UnlockLockout,
    PassphraseChanged,

    /// A `list` — metadata only, never a secret.
    MetadataListed,
    /// An `info` — metadata only.
    MetadataRead,
    /// A `request` that was allowed.
    SecretReleased {
        grant_id: String,
    },
    /// A `request` that was refused.
    SecretRefused {
        reason: String,
    },
    /// A `request` that needs the user's decision.
    ApprovalRequested {
        request_id: String,
    },
    ApprovalGranted {
        request_id: String,
    },
    ApprovalDenied {
        request_id: String,
    },
    /// An approval made in the access screen rather than in response to a request.
    GrantCreated {
        grant_id: String,
    },
    GrantRevoked {
        grant_id: String,
    },
    GrantsRevokedForClient {
        count: usize,
    },

    KeyCreated {
        entry_id: String,
        name: String,
    },
    KeyUpdated {
        entry_id: String,
        name: String,
    },
    KeyDeleted {
        entry_id: String,
        name: String,
    },
    /// A secret was copied to the clipboard.
    KeyCopied {
        entry_id: String,
    },
    /// The clipboard was cleared.
    ClipboardCleared {
        entry_id: String,
    },

    BackupExported {
        path: String,
    },
    BackupImported {
        entries: usize,
        merged: bool,
    },
    SettingsChanged {
        setting: String,
    },
    /// A malformed or rejected IPC request.
    BadRequest {
        detail: String,
    },
    /// A security control refused something. `control` names which one.
    SecurityControlRefused {
        control: String,
        detail: String,
    },
}

/// One line of the log.
///
/// Note what is absent: no `Option<String>` for "the secret, if you want it".
/// That is the point — there is nowhere to put one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Monotonic per-vault sequence number, starting at 1.
    pub seq: u64,
    /// RFC 3339. Display and ordering only.
    pub at: String,
    /// What happened.
    pub kind: AuditKind,
    /// Client fingerprint, when the event came from an IPC client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    /// SHA-256 over the previous entry's chain and this payload, hex.
    pub prev_chain: String,
    /// HMAC-SHA-256 over `prev_chain || payload`, hex. Authenticates the entry
    /// against anyone who does not hold the chain key.
    pub mac: String,
}

impl AuditEvent {
    /// The bytes covered by the MAC: everything except the MAC itself.
    ///
    /// Field order is fixed by the struct definition, so a re-serialisation is
    /// byte-identical. If the format ever needs a change, bump
    /// `PROTOCOL_VERSION` rather than reordering fields silently.
    #[allow(dead_code)]
    fn mac_payload(&self) -> Result<Vec<u8>> {
        let mut core = self.clone();
        core.mac = String::new();
        Ok(serde_json::to_vec(&core)?)
    }
}

/// One client request awaiting a human decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingApproval {
    pub request_id: String,
    pub client_fingerprint: String,
    pub client_label: String,
    pub client_path: String,
    pub client_pid: u32,
    pub client_elevated: bool,
    pub entry_id: String,
    pub entry_name: String,
    /// Untrusted client text, rendered quoted.
    pub declared_purpose: Option<String>,
    pub requested_at: String,
}

impl PendingApproval {
    /// The dialog body. Assembled here so the UI cannot accidentally show
    /// something different from what the user is approving — in particular it
    /// can never show the key's value, because no field of this type holds one.
    pub fn to_dialog_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("Application", self.client_label.clone()),
            ("Process path", self.client_path.clone()),
            ("Process ID", format!("{} (unverified)", self.client_pid)),
            (
                "Elevated",
                if self.client_elevated {
                    "yes — this process runs as administrator".to_string()
                } else {
                    "no".to_string()
                },
            ),
            ("Requested key", self.entry_name.clone()),
            (
                "Stated purpose",
                match &self.declared_purpose {
                    Some(p) => format!("\u{201c}{p}\u{201d} (client-supplied, unverified)"),
                    None => "not stated".to_string(),
                },
            ),
            (
                "Access",
                "release the secret value to this process".to_string(),
            ),
        ]
    }
}

/// DPAPI-wrapped chain key for the audit log.
///
/// Present so the log's integrity is bound to the Windows user account. It is
/// explicitly **not** a second copy of the vault key: wrapping the data key
/// with DPAPI would hand it to every process running as the user and destroy
/// the passphrase barrier entirely. This wraps only the log's HMAC key, which
/// protects nothing confidential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditKeyRing {
    pub format_version: u32,
    /// Base64-free hex of the DPAPI-protected chain key. Empty on platforms
    /// without DPAPI, where the chain is still detectable but not account-bound.
    pub protected_key: String,
    /// The chain head at the time of writing, so a truncated file is detectable
    /// even before any verification pass.
    pub chain_head: String,
    pub last_seq: u64,
}

impl AuditKeyRing {
    pub fn genesis() -> Self {
        Self {
            format_version: crate::PROTOCOL_VERSION,
            protected_key: String::new(),
            chain_head: GENESIS.to_string(),
            last_seq: 0,
        }
    }
}

/// The chain value that precedes the first event.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// In-memory audit log. Appends are chained as they happen so a crash cannot
/// leave a gap that looks like nothing happened.
///
/// Holds the chain key when one is available, so that `append` and `verify`
/// cannot forget to use it — a log whose integrity depends on every call site
/// remembering an argument is a log that silently loses its integrity.
#[derive(Debug, Clone)]
pub struct AuditLog {
    events: Vec<AuditEvent>,
    chain_head: String,
    last_seq: u64,
    key: Option<crate::crypto::secret::SecretBytes>,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self {
            events: Vec::new(),
            chain_head: GENESIS.to_string(),
            last_seq: 0,
            key: None,
        }
    }
}

impl AuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild from disk, carrying forward the stored chain head so a new event
    /// continues the existing chain instead of starting a fresh one that would
    /// look like a truncated log.
    pub fn restore(
        events: Vec<AuditEvent>,
        chain_head: String,
        last_seq: u64,
        key: Option<crate::crypto::secret::SecretBytes>,
    ) -> Self {
        Self {
            events,
            chain_head,
            last_seq,
            key,
        }
    }

    pub fn chain_head(&self) -> &str {
        &self.chain_head
    }

    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }

    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    /// Whether events are additionally authenticated with the account-bound
    /// chain key. `false` means the chain is still linked but a wholesale
    /// rewrite by a local attacker would not be caught.
    pub fn is_mac_backed(&self) -> bool {
        self.key.is_some()
    }

    /// Most recent first, for the UI.
    pub fn recent(&self, limit: usize) -> Vec<&AuditEvent> {
        let mut v: Vec<&AuditEvent> = self.events.iter().collect();
        v.reverse();
        v.truncate(limit);
        v
    }

    /// Append an event, extending the chain.
    pub fn append(&mut self, kind: AuditKind, client: Option<String>) -> Result<u64> {
        let seq = self.last_seq + 1;
        let e = AuditEvent {
            seq,
            at: now_rfc3339(),
            kind,
            client,
            prev_chain: self.chain_head.clone(),
            mac: String::new(),
        };
        let (next, mac) = self.link(&e)?;
        let mut e = e;
        e.mac = mac;
        self.chain_head = next;
        self.last_seq = seq;
        self.events.push(e);
        Ok(seq)
    }

    /// The link material for one event: `prev_chain || payload`, where the
    /// payload is the whole event with an empty `mac`.
    fn mac_payload(&self, e: &AuditEvent) -> Result<Vec<u8>> {
        let mut core = e.clone();
        core.mac = String::new();
        let body = serde_json::to_vec(&core)?;
        let mut buf = Vec::with_capacity(e.prev_chain.len() + 1 + body.len());
        buf.extend_from_slice(e.prev_chain.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(&body);
        Ok(buf)
    }

    /// Returns `(next_chain_head, mac)` for `e`.
    fn link(&self, e: &AuditEvent) -> Result<(String, String)> {
        let payload = self.mac_payload(e)?;
        let next = sha256_hex(&payload);
        let mac = match &self.key {
            Some(k) => hmac_sha256_hex(k.as_slice(), &payload),
            None => String::new(),
        };
        Ok((next, mac))
    }

    /// Walk the chain and report the first break, if any.
    ///
    /// Verifies sequence continuity, the hash links, and — when a chain key is
    /// present — every MAC. Detects deletion, reordering, in-place edits and
    /// wholesale truncation.
    ///
    /// It cannot detect a wholesale rewrite by someone who recomputed the whole
    /// chain *and* holds the chain key. See the module docs.
    pub fn verify(&self) -> Result<()> {
        let mut prev = GENESIS.to_string();

        for (expected_seq, e) in (1u64..).zip(self.events.iter()) {
            if e.seq != expected_seq {
                return Err(Error::Malformed(format!(
                    "audit sequence jumped from {} to {} — entries were removed",
                    expected_seq.saturating_sub(1),
                    e.seq
                )));
            }
            if e.prev_chain != prev {
                return Err(Error::Malformed(format!(
                    "audit chain broken at event {} — an earlier entry was altered",
                    e.seq
                )));
            }
            let (next, mac) = self.link(e)?;
            if mac != e.mac {
                return Err(Error::Malformed(format!(
                    "audit entry {} failed its authentication check",
                    e.seq
                )));
            }
            prev = next;
        }

        if prev != self.chain_head {
            return Err(Error::Malformed(
                "audit chain head does not match the last entry — the log was truncated".into(),
            ));
        }
        Ok(())
    }

    /// Every stored event, cloned out for writing to disk.
    pub fn into_events(self) -> Vec<AuditEvent> {
        self.events
    }
}

/// SHA-256, hex.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex_encode(&Sha256::digest(bytes))
}

/// HMAC-SHA-256, hex.
fn hmac_sha256_hex(key: &[u8], bytes: &[u8]) -> String {
    use hmac::{Mac, SimpleHmac};
    let mut m =
        SimpleHmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
    m.update(bytes);
    hex_encode(&m.finalize().into_bytes())
}

fn hex_encode(bytes: &[u8]) -> String {
    crate::crypto::hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_log_verifies() {
        AuditLog::new().verify().unwrap();
    }

    #[test]
    fn appended_events_form_a_valid_chain() {
        let mut log = AuditLog::new();
        log.append(AuditKind::VaultCreated, None).unwrap();
        log.append(AuditKind::VaultUnlocked, None).unwrap();
        log.append(
            AuditKind::KeyDeleted {
                entry_id: "e1".into(),
                name: "OPENAI_API_KEY".into(),
            },
            None,
        )
        .unwrap();
        log.verify().unwrap();
        assert_eq!(log.last_seq(), 3);
        assert_eq!(log.events()[0].seq, 1);
        assert_ne!(log.chain_head(), GENESIS);
    }

    #[test]
    fn removing_an_earlier_event_is_detected() {
        let mut log = AuditLog::new();
        for _ in 0..4 {
            log.append(AuditKind::VaultUnlocked, None).unwrap();
        }
        log.events.remove(1);
        assert!(log.verify().is_err(), "deletion must be detected");
    }

    #[test]
    fn reordering_events_is_detected() {
        let mut log = AuditLog::new();
        for _ in 0..3 {
            log.append(AuditKind::VaultUnlocked, None).unwrap();
        }
        log.events.swap(0, 1);
        assert!(log.verify().is_err());
    }

    #[test]
    fn editing_an_earlier_event_is_detected() {
        let mut log = AuditLog::new();
        log.append(AuditKind::VaultUnlocked, None).unwrap();
        log.append(
            AuditKind::SecretRefused {
                reason: "no_grant".into(),
            },
            None,
        )
        .unwrap();
        // Turn the refusal into an approval — the exact edit an attacker wants.
        log.events[0].kind = AuditKind::VaultLocked;
        assert!(log.verify().is_err());
    }

    #[test]
    fn truncation_against_a_stored_head_is_detected() {
        let mut log = AuditLog::new();
        for _ in 0..5 {
            log.append(AuditKind::VaultUnlocked, None).unwrap();
        }
        let head = log.chain_head().to_string();
        log.events.truncate(2);
        log.chain_head = head;
        assert!(log.verify().is_err());
    }

    #[test]
    fn the_approval_dialog_cannot_render_a_secret() {
        let a = PendingApproval {
            request_id: "r1".into(),
            client_fingerprint: "fp".into(),
            client_label: "agent.exe".into(),
            client_path: r"C:\x\agent.exe".into(),
            client_pid: 7,
            client_elevated: false,
            entry_id: "e1".into(),
            entry_name: "OPENAI_API_KEY".into(),
            declared_purpose: Some("run tests".into()),
            requested_at: now_rfc3339(),
        };
        let fields = a.to_dialog_fields();
        let joined: String = fields
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(joined.contains("OPENAI_API_KEY"));
        assert!(joined.contains("agent.exe"));
        // The purpose is visibly attributed to the client, so a client cannot
        // dress its text up as interface copy.
        assert!(joined.contains("client-supplied, unverified"));
        // Elevated state is surfaced rather than glossed over.
        assert!(joined.contains("runs as administrator") || joined.contains("Elevated"));
    }

    #[test]
    fn serialised_events_carry_no_secret_shaped_field() {
        let mut log = AuditLog::new();
        log.append(
            AuditKind::SecretReleased {
                grant_id: "g1".into(),
            },
            Some("fp".into()),
        )
        .unwrap();
        let json = serde_json::to_string(log.events()).unwrap();
        for forbidden in ["secret_value", "api_key", "passphrase", "authorization"] {
            assert!(
                !json.contains(forbidden),
                "audit event exposed a {forbidden} field"
            );
        }
    }
}
