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
//! Two independent mechanisms, and it is worth being precise about what each one
//! buys:
//!
//! * A **SHA-256 hash chain.** Each entry carries the digest of the previous
//!   entry plus its own payload, so removing, reordering or editing any earlier
//!   event breaks every later link, and truncation leaves a head that does not
//!   match. This works with no key material at all.
//! * An **HMAC over the same payload**, using a random 32-byte chain key stored
//!   under Windows DPAPI. The hash chain alone is defeated by anyone who simply
//!   recomputes it — the digests are not secret. The MAC is what catches a
//!   wholesale rewrite by a process that can edit the file but cannot unwrap
//!   the key.
//!
//! The MAC is only real when a [`ChainKeyProtector`] is installed and the key
//! survives a restart. Without one, [`AuditLog::is_mac_backed`] is `false` and
//! callers are expected to say so rather than imply the stronger guarantee.
//!
//! **Stated plainly: this is tamper-evidence, not tamper-proofing.** An attacker
//! who fully controls the user account can call DPAPI, rewrite the file and
//! recompute both chain and MAC. What the pair does buy is that casual
//! truncation, accidental deletion, offline editing with a text editor, and
//! scripted rewriting are all detected, and an investigator gets a chain they
//! can check.
//!
//! ## Not a plaintext-free log
//!
//! `audit.log` is written in the clear, because an audit log an investigator
//! cannot read without the vault passphrase would be close to useless. It
//! therefore does *not* contain secrets — the event types are structurally
//! incapable of that — but it does contain key names and client identity
//! strings. Client fingerprints are shortened by
//! [`crate::vault::shorten_identity`] before they are written for exactly this
//! reason. See `SECURITY.md` for what that does and does not hide.
//!
//! ## Backups
//!
//! The log ships inside the encrypted export, so it travels with the data it
//! describes.

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
    /// The bytes covered by the MAC and the chain link.
    ///
    /// `prev_chain || '|' || json(event with an empty mac)`. Deliberately lives
    /// here rather than on the struct so there is exactly one definition: an
    /// earlier version had a second, subtly different copy on `AuditEvent` that
    /// omitted `prev_chain`, which is the kind of divergence that makes a
    /// verifier compute the wrong digest while looking correct.
    pub fn link_payload(&self) -> Result<Vec<u8>> {
        let mut core = self.clone();
        core.mac = String::new();
        let body = serde_json::to_vec(&core)?;
        let mut buf = Vec::with_capacity(self.prev_chain.len() + 1 + body.len());
        buf.extend_from_slice(self.prev_chain.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(&body);
        Ok(buf)
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
/// Protects the audit chain key at rest.
///
/// A trait rather than a direct DPAPI call because the core crate denies
/// `unsafe_code`, and because the guarantee is platform-specific: the daemon
/// installs a DPAPI-backed implementation on Windows, and anything else gets
/// [`NoChainKeyProtection`] and an honestly unbacked log.
///
/// Binding the chain key to the account is what makes the MAC meaningful without
/// touching the passphrase barrier: DPAPI can only unwrap for the user whose
/// account produced the blob, whereas the vault's data key requires the
/// passphrase. The two are deliberately kept independent.
pub trait ChainKeyProtector: Send + Sync {
    /// Wrap `key` for storage. The output is opaque to the core.
    fn protect(&self, key: &[u8]) -> Result<Vec<u8>>;

    /// Unwrap a value produced by [`Self::protect`].
    fn unprotect(&self, blob: &[u8]) -> Result<Vec<u8>>;
}

/// The protector used when the platform offers none.
///
/// It stores nothing, so the chain key cannot survive a restart and the log
/// falls back to a bare hash chain. [`AuditLog::is_mac_backed`] reports `false`
/// and `AuditKeyRing::protected_key` is empty, so the weaker guarantee is
/// visible rather than implied.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoChainKeyProtection;

impl ChainKeyProtector for NoChainKeyProtection {
    fn protect(&self, _key: &[u8]) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
    fn unprotect(&self, _blob: &[u8]) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

/// The chain key's state on disk, alongside the head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditKeyRing {
    pub format_version: u32,
    /// Hex of the protected chain key.
    ///
    /// Empty when no [`ChainKeyProtector`] is installed — which is a real, weaker
    /// state and is reported rather than papered over.
    pub protected_key: String,
    /// The chain head at the time of writing, so a truncated file is detectable
    /// even before any verification pass.
    pub chain_head: String,
    pub last_seq: u64,
}

impl AuditKeyRing {
    /// A fresh keyring for a log that has not been written yet.
    pub fn genesis(protected_key: Vec<u8>) -> Self {
        Self {
            format_version: crate::PROTOCOL_VERSION,
            protected_key: crate::crypto::hex::encode(&protected_key),
            chain_head: GENESIS.to_string(),
            last_seq: 0,
        }
    }

    /// Whether a usable protected key is present.
    pub fn has_key(&self) -> bool {
        !self.protected_key.is_empty()
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
    /// Whether `chain_head` came from the keyring file rather than from the
    /// events themselves. See [`AuditLog::from_storage`].
    head_trusted: bool,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self {
            events: Vec::new(),
            chain_head: GENESIS.to_string(),
            last_seq: 0,
            key: None,
            head_trusted: true,
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
            head_trusted: true,
        }
    }

    /// Rebuild from disk, verifying against a head recorded elsewhere.
    ///
    /// `expected_head` is the chain head as stored in the keyring file — a
    /// *different* file from the log. That separation is the entire detection
    /// mechanism: someone who edits `audit.log` to hide an event has to edit
    /// `audit.keyring` too, and the two are not written at the same instant.
    ///
    /// Deriving the head from the events instead would make the check
    /// self-fulfilling — `verify` would compare the log's own last link against a
    /// value computed from that same log, and could never fail. That was a real
    /// mistake here: the first version of this function computed the head, and
    /// the tamper-detection test passed on a log that had been edited.
    ///
    /// When `expected_head` is `None` the head cannot be checked, so it is set
    /// to the computed one and the caller is expected to notice via
    /// [`AuditLog::head_is_trusted`]. Every other check — sequence continuity,
    /// links, MACs — still runs.
    pub fn from_storage(
        events: Vec<AuditEvent>,
        expected_head: Option<String>,
        key: Option<crate::crypto::secret::SecretBytes>,
    ) -> Result<Self> {
        let last_seq = events.iter().map(|e| e.seq).max().unwrap_or(0);
        let computed = Self::restore(events, GENESIS.to_string(), last_seq, key.clone());
        let head = computed.compute_head()?;
        let trusted = expected_head.is_some();
        Ok(Self::restore(
            computed.into_events(),
            expected_head.unwrap_or(head),
            last_seq,
            key,
        ))
        .map(|mut l| {
            l.head_trusted = trusted;
            l
        })
    }

    /// Whether the chain head was checked against a separately stored value.
    ///
    /// `false` means the links and MACs verified but the head was self-computed,
    /// so a wholesale *truncation* would not have been caught.
    pub fn head_is_trusted(&self) -> bool {
        self.head_trusted
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

    /// The chain key, for persisting it under the protector.
    pub fn chain_key(&self) -> Option<&[u8]> {
        self.key.as_ref().map(|k| k.as_slice())
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
        e.link_payload()
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
    ///
    /// ## Why it starts from the first stored event
    ///
    /// The walk begins at the first event's own `prev_chain` and `seq`, not at
    /// `GENESIS` and 1. The log on disk is a bounded window (see
    /// [`Vault::persist_audit`](crate::vault::Vault)), so its first retained
    /// event is not seq 1 — and a verifier that insisted on `GENESIS` would
    /// report a perfectly intact window as truncated. Starting from the first
    /// stored link verifies exactly what is present, which is what a verifier
    /// can honestly claim.
    pub fn verify(&self) -> Result<()> {
        let Some(first) = self.events.first() else {
            // An empty log is valid only if it has never had an event.
            return if self.chain_head == GENESIS {
                Ok(())
            } else {
                Err(Error::Malformed(
                    "the audit log is empty but records a chain head".into(),
                ))
            };
        };

        let mut prev = first.prev_chain.clone();

        for (offset, e) in self.events.iter().enumerate() {
            let expected = first.seq + offset as u64;
            if e.seq != expected {
                return Err(Error::Malformed(format!(
                    "audit sequence jumped from {} to {} — entries were removed",
                    expected.saturating_sub(1),
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

    /// The chain head implied by the stored events.
    ///
    /// Derived rather than read from the keyring so the value cannot disagree
    /// with the events it describes.
    pub fn compute_head(&self) -> Result<String> {
        let Some(mut prev) = self.events.first().map(|e| e.prev_chain.clone()) else {
            return Ok(GENESIS.to_string());
        };
        for e in &self.events {
            prev = self.link(e)?.0;
        }
        Ok(prev)
    }

    /// Every stored event, cloned out for writing to disk.
    pub fn into_events(self) -> Vec<AuditEvent> {
        self.events
    }

    /// The most recent `keep` events, oldest first.
    ///
    /// Used to bound the file the vault rewrites on every event. The retained
    /// events keep their original `seq` numbers, so the on-disk sequence has a
    /// visible gap at the front rather than pretending the log began at 1.
    pub fn trimmed(&self, keep: usize) -> Vec<AuditEvent> {
        if self.events.len() <= keep {
            return self.events.clone();
        }
        self.events[self.events.len() - keep..].to_vec()
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
