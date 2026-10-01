//! Request dispatch: the single gate every pipe request passes through.
//!
//! The transport (named pipe, framing, JSON) is the daemon's problem. This
//! module is the core's, because authorisation is a security decision and the
//! spec is explicit that no caller may skip a check. Putting it here means it is
//! covered by `cargo test` with no pipe, no process and no Windows API
//! involved — the security tests are ordinary unit tests.
//!
//! ## The order of checks
//!
//! 1. **Envelope** — version and id. A future client must not be able to send a
//!    `request` that this build interprets more permissively.
//! 2. **Tier** — is this client allowed to perform an operation of this tier at
//!    all? Checked before anything is read from the vault, so an agent-tier
//!    client asking to create a key is refused without touching storage.
//! 3. **Locked** — anything that needs the data key is refused while locked.
//!    `Lock` and `Status` are exempt, because their whole purpose is to work
//!    when locked.
//! 4. **The operation's own rules** — the grant check for `request`, the entry
//!    existence check, validation.
//!
//! An error at any step is returned immediately. There is no partial success
//! and no "best effort" continuation.

use serde::{Deserialize, Serialize};

use super::{Operation, OwnerCheck, Request, Response, Tier};
use crate::{
    error::{DenyReason, Error, Result},
    model::{grant::GrantMode, ApiKeyMetadata, ClientIdentity, Visibility},
    vault::Vault,
};

/// Everything known about a caller that did not come from the request body.
///
/// In particular the identity is resolved by the daemon from the pipe handle,
/// never parsed from the JSON — a client cannot name itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub identity: ClientIdentity,
    pub tier: Tier,
}

impl Caller {
    /// An agent-tier caller, for tests and for the CLI before it has resolved
    /// its own path.
    pub fn agent(identity: ClientIdentity) -> Self {
        Self {
            identity,
            tier: Tier::Agent,
        }
    }

    pub fn owner(identity: ClientIdentity) -> Self {
        Self {
            identity,
            tier: Tier::Owner,
        }
    }
}

/// Handles requests against a vault.
pub struct Dispatcher<'v> {
    vault: &'v mut Vault,
    owner: &'v OwnerCheck,
}

impl<'v> Dispatcher<'v> {
    pub fn new(vault: &'v mut Vault, owner: &'v OwnerCheck) -> Self {
        Self { vault, owner }
    }

    pub fn vault(&self) -> &Vault {
        self.vault
    }

    pub fn vault_mut(&mut self) -> &mut Vault {
        self.vault
    }

    /// The owner's expected image path, for the UI to display.
    pub fn owner_expected_path(&self) -> String {
        self.owner.expected_path()
    }

    /// Re-derive a caller's tier from its image path.
    ///
    /// The daemon calls this after resolving the process; a client cannot
    /// influence the result because the path comes from the kernel.
    pub fn tier_for(&self, identity: &ClientIdentity) -> Tier {
        self.owner.classify(&identity.image_path)
    }

    /// Handle one request. Never panics on client input.
    pub fn handle(&mut self, caller: &Caller, req: &Request) -> Response {
        match self.dispatch(caller, req) {
            Ok(result) => Response::ok(req.id.clone(), result),
            Err(e) => Response::err(req.id.clone(), e),
        }
    }

    /// Handle a raw line, for the daemon's read loop.
    pub fn handle_line(&mut self, caller: &Caller, line: &str) -> Response {
        match serde_json::from_str::<Request>(line) {
            Ok(req) => {
                // Envelope validation happens inside `dispatch`, so an invalid
                // version is reported with the same shape as any other refusal.
                let id = req.id.clone();
                let response = self.handle(caller, &req);
                if response.id.is_empty() && !id.is_empty() {
                    // Preserve the correlation id even for an envelope failure,
                    // so a client waiting on it gets an answer.
                    return Response { id, ..response };
                }
                response
            }
            Err(_) => Response::err("", Error::invalid("request", "malformed request line")),
        }
    }

    fn dispatch(&mut self, caller: &Caller, req: &Request) -> Result<serde_json::Value> {
        // 1. Envelope.
        req.validate()?;

        // 2. Tier. Before any storage access.
        let required = req.op.tier();
        if required == Tier::Owner && caller.tier < Tier::Owner {
            self.vault.record_refusal(
                &crate::audit::AuditKind::SecurityControlRefused {
                    control: "tier".into(),
                    detail: format!("{} is owner-only", req.op.name()),
                },
                Some(caller.identity.fingerprint()),
            )?;
            return Err(Error::denied(
                DenyReason::OperationNotAllowed,
                format!("{} is not available to this client", req.op.name()),
            ));
        }

        // 3. Locked.
        if req.op.requires_unlocked_vault() {
            self.vault.deny_if_locked()?;
        }

        // 4. The operation.
        match &req.op {
            Operation::List { provider } => {
                let filter = provider.as_deref().map(crate::model::known_provider);
                let entries = self.vault.list(&caller.identity, filter)?;
                self.vault
                    .record_metadata_read(&caller.identity.fingerprint(), entries.len())?;
                let out: Vec<super::ListEntry> =
                    entries.iter().map(|e| self.list_entry(e, caller)).collect();
                Ok(serde_json::to_value(super::ListResult { entries: out })?)
            }

            Operation::Info { entry } => {
                let meta = self.vault.info(&caller.identity, entry)?;
                self.vault
                    .record_metadata_read(&caller.identity.fingerprint(), 1)?;
                let grants = self.vault.grants_for(&caller.identity, &meta.id)?;
                Ok(serde_json::to_value(super::InfoResult {
                    name: meta.name,
                    id: meta.id,
                    provider: meta.provider,
                    display_name: meta.display_name,
                    description: meta.description,
                    capabilities: meta.capabilities,
                    available: true,
                    granted: grants.iter().any(|g| g.mine),
                    hidden: meta.visibility == Visibility::Hidden,
                    created_at: meta.created_at,
                    updated_at: meta.updated_at,
                    grants,
                })?)
            }

            Operation::Request { entry, purpose } => {
                let entry_id = self.vault.resolve_entry_id(entry)?;
                let secret =
                    self.vault
                        .request_secret(&caller.identity, &entry_id, purpose.clone())?;
                // The only place in the whole request path where a secret is
                // turned back into a `String`. It is written straight to the
                // pipe by the caller of `handle` and dropped immediately.
                let value = secret.to_zeroizing_string()?;
                let name = self.vault.entry_name(&entry_id)?;
                // `value` is a `Zeroizing<String>`; the clone is the only additional copy of
                // the secret this makes, and it is dropped as soon as the JSON
                // value is serialised.
                Ok(serde_json::to_value(super::RequestResult {
                    name,
                    value: value.to_string(),
                })?)
            }

            Operation::Status => Ok(serde_json::to_value(self.status())?),
            Operation::Lock => {
                self.vault.lock()?;
                Ok(serde_json::json!({ "locked": true }))
            }

            Operation::Init { passphrase } => {
                self.vault.create(passphrase.as_bytes())?;
                Ok(serde_json::json!({ "created": true }))
            }

            Operation::Unlock { passphrase } => {
                self.vault.unlock(passphrase.as_bytes())?;
                Ok(serde_json::json!({
                    "locked": false,
                    "auto_lock_in": self.vault.session().seconds_until_auto_lock(
                        &self.vault.settings().auto_lock
                    ),
                }))
            }

            Operation::Create {
                name,
                display_name,
                provider,
                description,
                capabilities,
                hidden,
                secret,
            } => {
                let entry = self.vault.create_entry(
                    name,
                    display_name,
                    provider,
                    description.clone(),
                    capabilities.clone(),
                    if *hidden {
                        Visibility::Hidden
                    } else {
                        Visibility::Discoverable
                    },
                    crate::crypto::SecretString::new(secret.as_bytes().to_vec()),
                )?;
                Ok(serde_json::to_value(entry)?)
            }

            Operation::Update {
                entry,
                display_name,
                provider,
                description,
                capabilities,
                hidden,
                secret,
            } => {
                let id = self.vault.resolve_entry_id(entry)?;
                let updated = self.vault.update_entry(
                    &id,
                    display_name,
                    provider,
                    description.clone(),
                    capabilities.clone(),
                    if *hidden {
                        Visibility::Hidden
                    } else {
                        Visibility::Discoverable
                    },
                )?;
                if let Some(s) = secret {
                    self.vault.update_secret(
                        &id,
                        crate::crypto::SecretString::new(s.as_bytes().to_vec()),
                    )?;
                }
                Ok(serde_json::to_value(updated)?)
            }

            Operation::Delete { entry } => {
                let id = self.vault.resolve_entry_id(entry)?;
                self.vault.delete_entry(&id)?;
                Ok(serde_json::json!({ "deleted": true }))
            }

            Operation::Copy { entry } => {
                let id = self.vault.resolve_entry_id(entry)?;
                let masked = self.vault.copy_to_clipboard(&id)?;
                Ok(serde_json::json!({ "masked": masked }))
            }

            Operation::Access => {
                let rows = self.vault.access_overview()?;
                Ok(serde_json::to_value(rows)?)
            }

            Operation::Grant {
                entry,
                client_fingerprint,
                client_label,
                mode,
                expires_at,
            } => {
                let id = self.vault.resolve_entry_id(entry)?;
                let grant_id = self.vault.grant_for_fingerprint(
                    &id,
                    client_fingerprint,
                    client_label,
                    mode.to_mode(*expires_at),
                )?;
                Ok(serde_json::json!({ "grant_id": grant_id }))
            }

            Operation::Revoke { grant_id } => {
                self.vault.revoke_grant(grant_id)?;
                Ok(serde_json::json!({ "revoked": true }))
            }

            Operation::RevokeClient { client_fingerprint } => {
                let n = self.vault.revoke_client(client_fingerprint)?;
                Ok(serde_json::json!({ "revoked": n }))
            }

            Operation::Approvals => Ok(serde_json::to_value(self.vault.pending_approvals())?),

            Operation::Resolve {
                request_id,
                entry,
                mode,
            } => {
                let id = self.vault.resolve_entry_id(entry)?;
                self.vault.resolve_approval(
                    request_id,
                    &caller.identity,
                    &id,
                    mode.to_mode(None),
                    None,
                    None,
                )?;
                Ok(serde_json::json!({ "resolved": true }))
            }

            Operation::GetSettings => Ok(serde_json::to_value(self.vault.settings())?),

            Operation::SetSettings { settings } => {
                let applied = self.vault.update_settings(settings.clone())?;
                Ok(serde_json::to_value(applied)?)
            }

            Operation::Audit { limit } => {
                let n = (*limit).clamp(1, 500);
                Ok(serde_json::to_value(self.vault.audit().recent(n))?)
            }

            Operation::BackupExport { path, passphrase } => {
                let written = self.vault.backup_export(path, passphrase.as_bytes())?;
                Ok(serde_json::json!({ "path": written }))
            }

            Operation::BackupImport {
                path,
                overwrite,
                passphrase,
            } => {
                let report = self
                    .vault
                    .backup_import(path, passphrase.as_bytes(), *overwrite)?;
                Ok(serde_json::to_value(report)?)
            }

            Operation::ChangePassphrase { current, new } => {
                self.vault
                    .change_passphrase(current.as_bytes(), new.as_bytes())?;
                Ok(serde_json::json!({ "changed": true }))
            }
        }
    }

    fn list_entry(&self, e: &ApiKeyMetadata, caller: &Caller) -> super::ListEntry {
        super::ListEntry {
            name: e.name.clone(),
            id: e.id.clone(),
            provider: e.provider.clone(),
            // "available" means the vault is open, not that the key works. TEAvault
            // never calls a provider to check, and this field must not be read as
            // a validity claim.
            available: true,
            capabilities: e.capabilities.clone(),
            display_name: e.display_name.clone(),
            description: e.description.clone(),
            granted: self.vault.is_granted(&caller.identity.fingerprint(), &e.id),
            hidden: e.visibility == Visibility::Hidden,
        }
    }

    fn status(&self) -> super::StatusResult {
        super::StatusResult {
            initialized: self.vault.is_initialized(),
            locked: !self.vault.is_unlocked(),
            entry_count: self.vault.entry_count().unwrap_or_default(),
            pending_approvals: self.vault.pending_approvals().len(),
            protocol: super::PROTOCOL,
            auto_lock_in: self
                .vault
                .session()
                .seconds_until_auto_lock(&self.vault.settings().auto_lock),
            kdf: self.vault.cost_summary(),
        }
    }
}

/// A grant as reported over the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGrant {
    pub mode: String,
    pub granted_at: String,
    pub expires_at: Option<i64>,
    pub consumed: bool,
    pub mine: bool,
}

impl From<(GrantMode, String, Option<i64>, bool, bool)> for WireGrant {
    fn from(v: (GrantMode, String, Option<i64>, bool, bool)) -> Self {
        Self {
            mode: v.0.label().to_string(),
            granted_at: v.1,
            expires_at: v.2,
            consumed: v.3,
            mine: v.4,
        }
    }
}
