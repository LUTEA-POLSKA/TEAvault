//! The high-level vault: the one object that enforces the security model.
//!
//! Every operation the product exposes is a method here, and every one of them
//! goes through the same order: refuse if locked → verify the caller → verify
//! the grant → then, and only then, touch the secret. There is no method that
//! returns a plaintext key without having asked [`GrantSet::decide`] first, and
//! there is no method that reaches storage while locked.
//!
//! ## The list/info/request split
//!
//! These three operations look similar and are deliberately not:
//!
//! | operation | needs a grant | can return a secret |
//! |---|---|---|
//! | `list`   | no, but respects [`Visibility`] | no — the type has no field for one |
//! | `info`   | no, but respects [`Visibility`] | no — same type |
//! | `request`| **yes** | yes, and only this one |
//!
//! `list` and `info` return [`ApiKeyMetadata`], which has no secret field, so
//! "metadata never leaks a key" is a property of the type rather than of a
//! code path someone has to remember.
//!
//! ## Unlocking is required even for metadata
//!
//! Metadata is encrypted at rest, because the list of providers a user has keys
//! for is itself information an unapproved local process should not get. The
//! cost is that a locked vault answers nothing, which is the safe direction to
//! err in.

use crate::{
    audit::{AuditEvent, AuditKeyRing, AuditKind, AuditLog, ChainKeyProtector, PendingApproval},
    crypto::{keyring::Keyring, secret::SecretString},
    error::{DenyReason, Error, Result},
    model::{client::ClientIdentity, grant::*, ApiKeyMetadata, KnownProvider, Visibility},
    paths::VaultPaths,
    session::Session,
    settings::Settings,
    storage::VaultStore,
};
use std::sync::Arc;

/// Everything a caller can ask of the vault.
pub struct Vault {
    paths: VaultPaths,
    store: VaultStore,
    keyring: Option<Keyring>,
    session: Session,
    settings: Settings,
    audit: AuditLog,
    pending: Vec<PendingApproval>,
    /// Windows clipboard, supplied by the daemon. Core has no `unsafe`.
    clipboard: Option<Box<dyn crate::clipboard::Clipboard>>,
    /// Copied secrets awaiting their clear deadline: `(entry id, value, at)`.
    ///
    /// Holds the plaintext value, which is a cost the design accepts so the
    /// clear can be conditional. Cleared as soon as the deadline passes or the
    /// user copies something else.
    clipboard_clears: Vec<(String, String, i64)>,
    /// The identity clipboard operations act under.
    owner_identity: Option<ClientIdentity>,
    /// Wraps the audit chain key for storage. `None` until the daemon installs
    /// one, and the log then stays a bare hash chain — reported through
    /// [`AuditLog::is_mac_backed`] rather than implied.
    audit_protector: Option<Arc<dyn ChainKeyProtector>>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("paths", &self.paths)
            .field("initialized", &self.keyring.is_some())
            .field("session", &self.session)
            .field("pending_approvals", &self.pending.len())
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Open the vault at `paths`, loading the keyring and settings if present.
    ///
    /// Does **not** unlock. A freshly constructed vault is locked, and that is
    /// the state after every process start — there is no auto-unlock path.
    pub fn open(paths: VaultPaths) -> Result<Self> {
        let store = VaultStore::new(paths.clone());
        let keyring = if paths.keyring().exists() {
            let bytes = crate::storage::atomic::read_optional(&paths.keyring())?
                .ok_or(Error::NotInitialized)?;
            Some(serde_json::from_slice(&bytes)?)
        } else {
            None
        };

        let settings = match crate::storage::atomic::read_optional(&paths.settings())? {
            Some(b) => serde_json::from_slice(&b).unwrap_or_default(),
            None => Settings::default(),
        };

        Ok(Self {
            paths,
            store,
            keyring,
            session: Session::new(),
            settings,
            audit: AuditLog::new(),
            pending: Vec::new(),
            clipboard: None,
            clipboard_clears: Vec::new(),
            owner_identity: None,
            audit_protector: None,
        })
    }

    /// Declare which identity clipboard operations act under.
    ///
    /// Set by the daemon from its own verified owner identity, so a copy
    /// operation still passes the grant check.
    pub fn set_owner_identity(&mut self, identity: ClientIdentity) {
        self.owner_identity = Some(identity);
    }

    pub fn paths(&self) -> &VaultPaths {
        &self.paths
    }

    pub fn is_initialized(&self) -> bool {
        self.keyring.is_some()
    }

    pub fn is_unlocked(&self) -> bool {
        self.session.is_unlocked()
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    pub fn pending_approvals(&self) -> &[PendingApproval] {
        &self.pending
    }

    /// The KDF cost, for the unlock screen.
    pub fn cost_summary(&self) -> String {
        self.keyring
            .as_ref()
            .map(Keyring::cost_summary)
            .unwrap_or_else(|| "argon2id (no vault yet)".into())
    }

    // ---------------------------------------------------------------- setup

    /// Create a new vault.
    ///
    /// Refuses if one already exists — a fresh `init` must never be able to
    /// silently destroy an existing vault, because that is the one mistake
    /// that is unrecoverable.
    pub fn create(&mut self, passphrase: &[u8]) -> Result<()> {
        if self.is_initialized() {
            return Err(Error::AlreadyInitialized);
        }
        let min = self.settings.min_passphrase_chars.max(8);
        if passphrase.len() < min as usize {
            return Err(Error::invalid(
                "passphrase",
                format!("must be at least {min} characters"),
            ));
        }

        self.paths.ensure_dir()?;
        let (keyring, dek) = Keyring::create(passphrase)?;
        self.store.write_raw(&VaultStore::empty_sealed(&dek)?)?;
        crate::storage::atomic::write_atomic(
            &self.paths.keyring(),
            &serde_json::to_vec(&keyring)?,
        )?;
        self.keyring = Some(keyring);

        self.session
            .unlock(self.keyring.as_ref().expect("just set"), passphrase)?;
        self.audit.append(AuditKind::VaultCreated, None)?;
        self.persist_audit()?;
        Ok(())
    }

    /// Unlock with the master passphrase.
    pub fn unlock(&mut self, passphrase: &[u8]) -> Result<()> {
        if self.keyring.is_none() {
            return Err(Error::NotInitialized);
        }
        // The session needs `&mut`, the keyring `&`. Deriving first would need
        // to hold the keyring borrow across the mutation, so clone the keyring:
        // it is 200 bytes of public parameters plus one ciphertext, and it
        // contains no secret — the data key is still sealed inside it.
        let keyring = self.keyring.clone().expect("checked above");

        let outcome = self.session.unlock(&keyring, passphrase);

        match outcome {
            Ok(()) => {
                self.audit.append(AuditKind::VaultUnlocked, None)?;
                self.persist_audit()?;
                Ok(())
            }
            Err(e @ Error::AttemptsExhausted { .. }) => {
                self.audit.append(AuditKind::UnlockLockout, None)?;
                self.persist_audit()?;
                Err(e)
            }
            Err(e) => {
                self.audit.append(AuditKind::UnlockFailed, None)?;
                self.persist_audit()?;
                Err(e)
            }
        }
    }

    /// Lock, wiping the data key. Idempotent.
    pub fn lock(&mut self) -> Result<()> {
        let was = self.session.lock();
        // Pending approvals belong to an unlocked session. Carrying them across
        // a lock would let a request approved minutes later release a key the
        // user thought they had put away.
        self.pending.clear();
        if was {
            self.audit.append(AuditKind::VaultLocked, None)?;
            self.persist_audit()?;
        }
        Ok(())
    }

    /// Change the master passphrase. Requires an unlocked vault.
    ///
    /// Re-wraps the data key under a new passphrase. Entries are not
    /// re-encrypted, so there is no window in which a crash loses them.
    pub fn change_passphrase(&mut self, current: &[u8], new: &[u8]) -> Result<()> {
        let min = self.settings.min_passphrase_chars.max(8);
        if new.len() < min as usize {
            return Err(Error::invalid(
                "passphrase",
                format!("must be at least {min} characters"),
            ));
        }
        let Some(keyring) = self.keyring.as_mut() else {
            return Err(Error::NotInitialized);
        };
        // Prove the current passphrase before touching anything.
        let dek = keyring.unwrap_dek(current)?;
        keyring.rewrap(&dek, new)?;
        crate::storage::atomic::write_atomic(&self.paths.keyring(), &serde_json::to_vec(keyring)?)?;
        drop(dek);
        self.audit.append(AuditKind::PassphraseChanged, None)?;
        self.persist_audit()?;
        Ok(())
    }

    // ------------------------------------------------------------ operations

    /// `list`: metadata for the entries this client may see.
    ///
    /// Never returns a secret value — [`ApiKeyMetadata`] has no field for one.
    pub fn list(
        &self,
        client: &ClientIdentity,
        provider: Option<KnownProvider>,
    ) -> Result<Vec<ApiKeyMetadata>> {
        self.session.deny_if_locked()?;
        let dek = self.session.require_dek()?;
        let index = self.store.read_index(dek)?;
        let fp = client.fingerprint();
        let now = model_now();

        Ok(index
            .entries
            .iter()
            .filter(|e| {
                e.visibility == Visibility::Discoverable
                    || index.grants.has_any_grant_for(&fp, &e.id)
            })
            .filter(|e| match &provider {
                None => true,
                Some(p) => crate::model::known_provider(&e.provider) == *p,
            })
            .filter(|e| !index.grants.is_denied(&fp, &e.id, now))
            .cloned()
            .collect())
    }

    /// `info`: the metadata of one entry.
    ///
    /// Accepts an id *or* a variable name, because an agent only knows the name
    /// it wants to export while the UI has an id from a list it just rendered.
    ///
    /// Refuses for an entry the client may not know exists, so the error does
    /// not confirm the presence of a hidden key.
    pub fn info(&self, client: &ClientIdentity, needle: &str) -> Result<ApiKeyMetadata> {
        self.session.deny_if_locked()?;
        if needle.is_empty() {
            return Err(Error::invalid("entry", "must not be empty"));
        }
        let dek = self.session.require_dek()?;
        let index = self.store.read_index(dek)?;
        let fp = client.fingerprint();

        let entry = index
            .entries
            .iter()
            .find(|e| e.id == needle || e.name == needle)
            .ok_or_else(|| Error::not_found("entry", needle))?;

        if entry.visibility == Visibility::Hidden && !index.grants.has_any_grant_for(&fp, &entry.id)
        {
            return Err(Error::denied(
                DenyReason::NoGrant,
                "no grant covers this entry",
            ));
        }
        if index.grants.is_denied(&fp, &entry.id, model_now()) {
            return Err(Error::denied(
                DenyReason::DeniedByUser,
                "access to this entry was denied",
            ));
        }
        Ok(entry.clone())
    }

    /// `request`: release the secret for exactly one entry to one client.
    ///
    /// The order below is the security contract:
    ///
    /// 1. refuse while locked,
    /// 2. confirm the entry exists and is not denied to this client,
    /// 3. ask [`GrantSet::decide`],
    /// 4. only then decrypt that one secret,
    /// 5. spend a one-shot grant,
    /// 6. log the release — never the value.
    ///
    /// If no grant exists the call does not fail outright: it registers a
    /// [`PendingApproval`] and returns [`Error::NeedsConfirmation`], so the
    /// daemon can raise the dialog. A client cannot bring its own grant.
    pub fn request_secret(
        &mut self,
        client: &ClientIdentity,
        entry_id: &str,
        purpose: Option<String>,
    ) -> Result<SecretString> {
        self.session.deny_if_locked()?;
        let dek = self.session.require_dek()?;
        let index = self.store.read_index(dek)?;
        let fp = client.fingerprint();
        let now = model_now();

        let entry = index
            .entries
            .iter()
            .find(|e| e.id == entry_id)
            .ok_or_else(|| Error::not_found("entry", entry_id))?;

        if index.grants.is_denied(&fp, entry_id, now) {
            self.audit.append(
                AuditKind::SecretRefused {
                    reason: DenyReason::DeniedByUser.code().into(),
                },
                Some(fp.clone()),
            )?;
            self.persist_audit()?;
            return Err(Error::denied(
                DenyReason::DeniedByUser,
                "access to this entry was denied",
            ));
        }

        let grant_id = match index.grants.decide(&fp, entry_id, now) {
            Decision::Allowed(id) => id,
            Decision::Refused(reason) => {
                self.audit.append(
                    AuditKind::SecretRefused {
                        reason: reason.code().into(),
                    },
                    Some(fp.clone()),
                )?;
                self.persist_audit()?;
                return Err(Error::denied(reason, "no usable grant for this entry"));
            }
            Decision::NeedsApproval => {
                let pending = PendingApproval {
                    request_id: uuid::Uuid::new_v4().to_string(),
                    client_fingerprint: fp.clone(),
                    client_label: client.describe(),
                    client_path: client.image_path.clone(),
                    client_pid: client.pid,
                    client_elevated: client.elevated,
                    entry_id: entry.id.clone(),
                    entry_name: entry.name.clone(),
                    declared_purpose: purpose,
                    requested_at: crate::model::now_rfc3339(),
                };
                self.audit.append(
                    AuditKind::ApprovalRequested {
                        request_id: pending.request_id.clone(),
                    },
                    Some(fp.clone()),
                )?;
                self.persist_audit()?;
                let request_id = pending.request_id.clone();
                self.pending.push(pending);
                return Err(Error::NeedsConfirmation(
                    crate::error::ConfirmationRequired {
                        request_id,
                        entry_id: entry_id.to_string(),
                        purpose: None,
                    },
                ));
            }
        };

        // Everything above was metadata. This is the first line that decrypts.
        let secret = self.store.get_secret(dek, entry_id)?;

        // A one-shot grant is spent only after the secret was actually
        // produced, so a failed decrypt does not burn the user's approval.
        if index.grants.is_one_shot(&grant_id) {
            self.spend_grant(&grant_id)?;
        }

        self.audit.append(
            AuditKind::SecretReleased {
                grant_id: grant_id.clone(),
            },
            Some(fp),
        )?;
        self.persist_audit()?;
        Ok(secret)
    }

    // -------------------------------------------------------- entry editing

    /// Add an entry. Requires an unlocked vault.
    #[allow(clippy::too_many_arguments)]
    pub fn create_entry(
        &mut self,
        name: &str,
        display_name: &str,
        provider: &str,
        description: Option<String>,
        capabilities: Vec<String>,
        visibility: Visibility,
        secret: SecretString,
    ) -> Result<ApiKeyMetadata> {
        self.session.deny_if_locked()?;
        crate::model::validate_var_name(name)?;
        if display_name.trim().is_empty() {
            return Err(Error::invalid("display_name", "must not be empty"));
        }
        if secret.is_empty() {
            return Err(Error::invalid("secret", "must not be empty"));
        }

        let dek = self.session.require_dek()?;
        let entry = ApiKeyMetadata {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            display_name: display_name.trim().to_string(),
            provider: provider.trim().to_string(),
            description,
            capabilities,
            created_at: crate::model::now_rfc3339(),
            updated_at: crate::model::now_rfc3339(),
            visibility,
        };
        let id = entry.id.clone();

        self.store.update_index(dek, |index| -> Result<()> {
            if index.entries.iter().any(|e| e.name == entry.name) {
                return Err(Error::invalid(
                    "name",
                    format!("an entry named {} already exists", entry.name),
                ));
            }
            index.entries.push(entry.clone());
            Ok(())
        })?;

        self.store.put_secret(dek, &id, &secret)?;
        self.audit.append(
            AuditKind::KeyCreated {
                entry_id: id,
                name: name.to_string(),
            },
            None,
        )?;
        self.persist_audit()?;
        Ok(entry)
    }

    /// Update an entry's metadata. The secret is untouched.
    pub fn update_entry(
        &mut self,
        entry_id: &str,
        display_name: &str,
        provider: &str,
        description: Option<String>,
        capabilities: Vec<String>,
        visibility: Visibility,
    ) -> Result<ApiKeyMetadata> {
        self.session.deny_if_locked()?;
        let dek = self.session.require_dek()?;
        let updated = self
            .store
            .update_index(dek, |index| -> Result<ApiKeyMetadata> {
                let e = index
                    .entries
                    .iter_mut()
                    .find(|e| e.id == entry_id)
                    .ok_or_else(|| Error::not_found("entry", entry_id))?;
                if display_name.trim().is_empty() {
                    return Err(Error::invalid("display_name", "must not be empty"));
                }
                e.display_name = display_name.trim().to_string();
                e.provider = provider.trim().to_string();
                e.description = description;
                e.capabilities = capabilities;
                e.visibility = visibility;
                e.updated_at = crate::model::now_rfc3339();
                Ok(e.clone())
            })?;

        self.audit.append(
            AuditKind::KeyUpdated {
                entry_id: updated.id.clone(),
                name: updated.name.clone(),
            },
            None,
        )?;
        self.persist_audit()?;
        Ok(updated)
    }

    /// Replace an entry's secret, keeping its metadata.
    pub fn update_secret(&mut self, entry_id: &str, secret: SecretString) -> Result<()> {
        self.session.deny_if_locked()?;
        if secret.is_empty() {
            return Err(Error::invalid("secret", "must not be empty"));
        }
        let dek = self.session.require_dek()?;
        // Confirm the entry exists before writing a ciphertext nothing will
        // ever read.
        let index = self.store.read_index(dek)?;
        let name = index
            .entries
            .iter()
            .find(|e| e.id == entry_id)
            .map(|e| e.name.clone())
            .ok_or_else(|| Error::not_found("entry", entry_id))?;

        self.store.put_secret(dek, entry_id, &secret)?;
        self.audit.append(
            AuditKind::KeyUpdated {
                entry_id: entry_id.to_string(),
                name,
            },
            None,
        )?;
        self.persist_audit()?;
        Ok(())
    }

    /// Delete an entry, its ciphertext and every grant for it.
    pub fn delete_entry(&mut self, entry_id: &str) -> Result<()> {
        self.session.deny_if_locked()?;
        let dek = self.session.require_dek()?;
        let name = self.store.update_index(dek, |index| -> Result<String> {
            let e = index
                .entries
                .iter()
                .position(|e| e.id == entry_id)
                .ok_or_else(|| Error::not_found("entry", entry_id))?;
            let removed = index.entries.remove(e);
            // Grants for a deleted entry would outlive the thing they describe,
            // and would silently start matching a future entry that reuses the
            // id. Remove them in the same transaction.
            index.grants.retain_entries(|id| id != entry_id);
            Ok(removed.name)
        })?;
        self.store.remove_secret(entry_id)?;

        self.audit.append(
            AuditKind::KeyDeleted {
                entry_id: entry_id.to_string(),
                name,
            },
            None,
        )?;
        self.persist_audit()?;
        Ok(())
    }

    // ------------------------------------------------------------- access

    /// Every entry with its grants, for the access-management screen.
    pub fn access_overview(&self) -> Result<Vec<(ApiKeyMetadata, Vec<Grant>)>> {
        self.session.deny_if_locked()?;
        let dek = self.session.require_dek()?;
        let index = self.store.read_index(dek)?;
        Ok(index
            .entries
            .iter()
            .map(|e| {
                (
                    e.clone(),
                    index
                        .grants
                        .grants_for(&e.id)
                        .into_iter()
                        .cloned()
                        .collect(),
                )
            })
            .collect())
    }

    /// Answer a pending request.
    ///
    /// `mode` is what the user chose. A `Deny` is stored like any other grant
    /// so that it survives a restart and takes precedence over older approvals.
    ///
    /// Note this does **not** require the caller's identity to match the
    /// requesting client's: the owner UI answers on the *user's* behalf, not as
    /// the client. The protection is that this method is only reachable through
    /// the owner tier, which the dispatcher enforces from the verified image
    /// path. A client cannot bring its own approval request into existence
    /// either — only `request` creates one, and that needs an unlock first.
    pub fn resolve_approval(
        &mut self,
        request_id: &str,
        _answering: &ClientIdentity,
        entry_id: &str,
        mode: GrantMode,
        purpose: Option<String>,
    ) -> Result<()> {
        let Some(pos) = self.pending.iter().position(|p| p.request_id == request_id) else {
            return Err(Error::not_found("pending request", request_id));
        };
        let pending = self.pending.remove(pos);

        // The answer must apply to the request actually being held. Silently
        // approving a different entry would be the worst possible outcome here.
        if pending.entry_id != entry_id {
            self.pending.push(pending);
            return Err(Error::invalid(
                "entry_id",
                "does not match the pending request",
            ));
        }

        self.session.deny_if_locked()?;
        let dek = self.session.require_dek()?;

        let grant = Grant::new(
            pending.client_fingerprint.clone(),
            pending.client_label.clone(),
            entry_id.to_string(),
            mode.clone(),
        )
        .with_purpose(purpose.or(pending.declared_purpose.clone()));

        let grant_id = grant.id.clone();
        let denied = mode.is_deny();

        self.store.update_index(dek, |index| -> Result<()> {
            index.grants.upsert(grant);
            Ok(())
        })?;

        let kind = if denied {
            AuditKind::ApprovalDenied {
                request_id: request_id.to_string(),
            }
        } else {
            AuditKind::ApprovalGranted {
                request_id: request_id.to_string(),
            }
        };
        self.audit
            .append(kind, Some(pending.client_fingerprint.clone()))?;
        if !denied {
            self.audit
                .append(AuditKind::GrantCreated { grant_id }, None)?;
        }
        self.persist_audit()?;
        Ok(())
    }

    /// Create a grant directly from the access screen, without a pending
    /// request. Requires an unlocked vault — this is an owner action.
    pub fn create_grant(
        &mut self,
        client: &ClientIdentity,
        entry_id: &str,
        mode: GrantMode,
    ) -> Result<String> {
        self.session.deny_if_locked()?;
        let dek = self.session.require_dek()?;
        let index = self.store.read_index(dek)?;
        if !index.entries.iter().any(|e| e.id == entry_id) {
            return Err(Error::not_found("entry", entry_id));
        }
        let grant = Grant::new(
            client.fingerprint(),
            client.describe(),
            entry_id.to_string(),
            mode,
        );
        let id = grant.id.clone();
        let gid = id.clone();
        self.store.update_index(dek, |index| -> Result<()> {
            index.grants.upsert(grant);
            Ok(())
        })?;
        self.audit
            .append(AuditKind::GrantCreated { grant_id: gid }, None)?;
        self.persist_audit()?;
        Ok(id)
    }

    /// Revoke one grant.
    pub fn revoke_grant(&mut self, grant_id: &str) -> Result<()> {
        self.session.deny_if_locked()?;
        let dek = self.session.require_dek()?;
        self.store
            .update_index(dek, |index| index.grants.revoke(grant_id))?;
        self.audit.append(
            AuditKind::GrantRevoked {
                grant_id: grant_id.to_string(),
            },
            None,
        )?;
        self.persist_audit()?;
        Ok(())
    }

    /// Revoke every grant for one client.
    pub fn revoke_client(&mut self, fingerprint: &str) -> Result<usize> {
        self.session.deny_if_locked()?;
        let dek = self.session.require_dek()?;
        let count = self
            .store
            .update_index(dek, |index| Ok(index.grants.revoke_client(fingerprint)))?;
        self.audit
            .append(AuditKind::GrantsRevokedForClient { count }, None)?;
        self.persist_audit()?;
        Ok(count)
    }

    /// Drop grants that can no longer act, so the access screen shows only live
    /// permissions.
    pub fn prune_grants(&mut self) -> Result<usize> {
        self.session.deny_if_locked()?;
        let dek = self.session.require_dek()?;
        self.store
            .update_index(dek, |index| Ok(index.grants.prune(model_now())))
    }

    // ------------------------------------------------------------- settings

    /// Apply new settings. Validated first, so a rejected change leaves the
    /// old ones in place.
    pub fn update_settings(&mut self, next: Settings) -> Result<Settings> {
        let mut candidate = self.settings.clone();
        candidate.apply(next)?;
        crate::storage::atomic::write_atomic(
            &self.paths.settings(),
            &serde_json::to_vec(&candidate)?,
        )?;
        self.audit.append(
            AuditKind::SettingsChanged {
                setting: "settings".into(),
            },
            None,
        )?;
        self.persist_audit()?;
        self.settings = candidate;
        Ok(self.settings.clone())
    }

    // -------------------------------------------------------------- helpers

    /// Mark a one-shot grant spent, inside the same transaction as anything
    /// else that has to happen atomically.
    fn spend_grant(&mut self, grant_id: &str) -> Result<()> {
        let dek = self.session.require_dek()?;
        let ok = self
            .store
            .update_index(dek, |index| Ok(index.grants.consume(grant_id)))?;
        if !ok {
            // The grant vanished or was not spendable between the decision and
            // here. Fail closed rather than releasing the secret on an
            // unverified assumption.
            return Err(Error::denied(
                DenyReason::InvalidRequest,
                "the grant could not be spent",
            ));
        }
        Ok(())
    }

    fn persist_audit(&mut self) -> Result<()> {
        self.paths.ensure_dir()?;
        let events = self.audit.clone().into_events();
        let bytes = serde_json::to_vec(&events)?;
        crate::storage::atomic::write_atomic(&self.paths.audit_log(), &bytes)?;
        let protected_key = match (self.audit_protector.as_deref(), self.audit.chain_key()) {
            (Some(p), Some(key)) => p.protect(key)?,
            // Either no protector or no key yet: record it honestly rather than
            // writing an empty string that reads like a stored key.
            _ => Vec::new(),
        };
        let keyring = AuditKeyRing {
            format_version: crate::PROTOCOL_VERSION,
            protected_key: crate::crypto::hex::encode(&protected_key),
            chain_head: self.audit.chain_head().to_string(),
            last_seq: self.audit.last_seq(),
        };
        crate::storage::atomic::write_atomic(
            &self.paths.audit_keyring(),
            &serde_json::to_vec(&keyring)?,
        )?;
        Ok(())
    }

    /// Load the audit log from disk, verifying the chain before trusting it.
    pub fn load_audit(&mut self) -> Result<usize> {
        let Some(bytes) = crate::storage::atomic::read_optional(&self.paths.audit_log())? else {
            return Ok(0);
        };
        let events: Vec<AuditEvent> = serde_json::from_slice(&bytes)?;
        let stored = crate::storage::atomic::read_optional(&self.paths.audit_keyring())?
            .and_then(|b| serde_json::from_slice::<AuditKeyRing>(&b).ok())
            .unwrap_or_else(|| AuditKeyRing::genesis(Vec::new()));

        // Unwrap the chain key with whichever protector is installed. A keyring
        // that cannot be unwrapped is not a reason to skip verification — the
        // chain still has to check out — so it degrades to an unbacked log.
        let key = match (
            self.audit_protector.as_deref(),
            crate::crypto::hex::decode(&stored.protected_key).ok(),
        ) {
            (Some(p), Some(blob)) if !blob.is_empty() => p
                .unprotect(&blob)
                .ok()
                .map(|k| crate::crypto::secret::SecretBytes::new(k)),
            _ => None,
        };
        let log = AuditLog::from_storage(events, Some(stored.chain_head), key)?;
        log.verify()?;
        let n = log.events().len();
        self.audit = log;
        Ok(n)
    }

    // ------------------------------------------------- dispatcher support

    /// Attach a clipboard backend. Without one, copying a key fails loudly.
    pub fn set_clipboard(&mut self, clipboard: Box<dyn crate::clipboard::Clipboard>) {
        self.clipboard = Some(clipboard);
    }

    /// Install the platform's chain-key protector, so the audit log's MACs are
    /// account-bound and survive a restart.
    ///
    /// Set by the daemon before the first event is written. Without it the log
    /// is still a hash chain, but anyone able to edit the file can recompute it —
    /// and [`AuditLog::is_mac_backed`] reports `false` so the weaker guarantee is
    /// visible rather than implied.
    pub fn set_audit_protector(&mut self, protector: Arc<dyn ChainKeyProtector>) {
        self.audit_protector = Some(protector);
    }

    /// Refuse while locked, with the reason that is actually true.
    pub fn deny_if_locked(&self) -> Result<()> {
        self.session.deny_if_locked()
    }

    /// Resolve an entry id from either an id or a variable name.
    ///
    /// Both are accepted because the two callers have different needs: an agent
    /// only knows the variable name it wants to export, while the UI has an id
    /// from a list it just rendered.
    pub fn resolve_entry_id(&self, needle: &str) -> Result<String> {
        if needle.is_empty() {
            return Err(Error::invalid("entry", "must not be empty"));
        }
        self.session.deny_if_locked()?;
        let dek = self.session.require_dek()?;
        let index = self.store.read_index(dek)?;
        index
            .entries
            .iter()
            .find(|e| e.id == needle || e.name == needle)
            .map(|e| e.id.clone())
            .ok_or_else(|| Error::not_found("entry", needle))
    }

    /// The variable name for an entry id.
    pub fn entry_name(&self, entry_id: &str) -> Result<String> {
        let dek = self.session.require_dek()?;
        let index = self.store.read_index(dek)?;
        index
            .entries
            .iter()
            .find(|e| e.id == entry_id)
            .map(|e| e.name.clone())
            .ok_or_else(|| Error::not_found("entry", entry_id))
    }

    /// How many entries exist. Zero when locked rather than an error, because
    /// `status` must work while locked.
    pub fn entry_count(&self) -> Result<usize> {
        if !self.session.is_unlocked() {
            return Ok(0);
        }
        let dek = self.session.require_dek()?;
        Ok(self.store.read_index(dek)?.entries.len())
    }

    /// Whether a client currently holds a usable grant for an entry.
    pub fn is_granted(&self, client_fingerprint: &str, entry_id: &str) -> bool {
        if !self.session.is_unlocked() {
            return false;
        }
        let Ok(dek) = self.session.require_dek() else {
            return false;
        };
        let Ok(index) = self.store.read_index(dek) else {
            return false;
        };
        matches!(
            index
                .grants
                .decide(client_fingerprint, entry_id, model_now()),
            Decision::Allowed(_)
        )
    }

    /// The grants applying to one client and entry, as wire views.
    ///
    /// Only the requesting client's own grants are returned. Reporting other
    /// clients' approvals would let one agent enumerate who else has access.
    pub fn grants_for(
        &self,
        client: &ClientIdentity,
        entry_id: &str,
    ) -> Result<Vec<crate::ipc::GrantView>> {
        let dek = self.session.require_dek()?;
        let index = self.store.read_index(dek)?;
        let fp = client.fingerprint();
        Ok(index
            .grants
            .grants_for(entry_id)
            .into_iter()
            .filter(|g| g.client_fingerprint == fp)
            .map(|g| crate::ipc::GrantView {
                mode: g.mode.label().to_string(),
                granted_at: g.granted_at.clone(),
                expires_at: match &g.mode {
                    GrantMode::AlwaysAllow { expires_at } => *expires_at,
                    _ => None,
                },
                consumed: g.consumed,
                mine: true,
            })
            .collect())
    }

    /// Create a grant for a fingerprint recorded earlier, e.g. one the user
    /// approved in the access screen.
    pub fn grant_for_fingerprint(
        &mut self,
        entry_id: &str,
        client_fingerprint: &str,
        client_label: &str,
        mode: GrantMode,
    ) -> Result<String> {
        self.session.deny_if_locked()?;
        if client_fingerprint.trim().is_empty() {
            return Err(Error::invalid("client_fingerprint", "must not be empty"));
        }
        let dek = self.session.require_dek()?;
        let index = self.store.read_index(dek)?;
        if !index.entries.iter().any(|e| e.id == entry_id) {
            return Err(Error::not_found("entry", entry_id));
        }

        let grant = Grant::new(client_fingerprint, client_label, entry_id, mode);
        let id = grant.id.clone();
        let gid = id.clone();
        self.store.update_index(dek, |index| {
            index.grants.upsert(grant);
            Ok(())
        })?;
        self.audit
            .append(AuditKind::GrantCreated { grant_id: gid }, None)?;
        self.persist_audit()?;
        Ok(id)
    }

    /// Copy an entry's secret to the clipboard for the owner's manual use.
    ///
    /// Returns the masked form so the caller can show what was copied without
    /// the value. Requires an explicit grant *for this client*, exactly like an
    /// agent request: copying to the clipboard is still a release of the
    /// secret, and clipboard readers are not a smaller risk than a pipe reader.
    pub fn copy_to_clipboard(&mut self, entry_id: &str) -> Result<String> {
        let identity = self.clipboard_identity()?;
        let secret =
            self.request_secret(&identity, entry_id, Some("copied by the owner".into()))?;
        let masked = secret.masked();
        let text = secret.to_zeroizing_string()?;

        let Some(clip) = self.clipboard.as_ref() else {
            return Err(Error::io(
                "clipboard",
                std::io::Error::other("no clipboard backend is available"),
            ));
        };
        clip.set(&text)?;
        self.clipboard_clears
            .push((entry_id.to_string(), text.to_string(), self.clipboard_ttl()));

        self.audit.append(
            AuditKind::KeyCopied {
                entry_id: entry_id.into(),
            },
            None,
        )?;
        self.persist_audit()?;
        Ok(masked)
    }

    /// Clear the clipboard entries that are still ours and have expired.
    ///
    /// Called from the daemon's one-shot timer, not from a poll: one wake-up
    /// per copied key, then it is done.
    pub fn run_clipboard_clears(&mut self) {
        let now = model_now();
        let due: Vec<(String, String)> = self
            .clipboard_clears
            .iter()
            .filter(|(_, _, at)| *at <= now)
            .map(|(id, text, _)| (id.clone(), text.clone()))
            .collect();
        if due.is_empty() {
            return;
        }

        let Some(clip) = self.clipboard.as_ref() else {
            self.clipboard_clears.clear();
            return;
        };

        for (entry_id, expected) in due {
            // Only wipe when the clipboard still holds our value. Otherwise the
            // user copied something else in the meantime and destroying it
            // would be data loss.
            let ours = clip.clear_if_unchanged(&expected).unwrap_or(false);
            if ours {
                let _ = self.audit.append(
                    AuditKind::ClipboardCleared {
                        entry_id: entry_id.clone(),
                    },
                    None,
                );
            }
            // Either way our record goes: either we cleared it, or it is no
            // longer ours to clear.
            self.clipboard_clears.retain(|(id, _, _)| *id != entry_id);
        }
        let _ = self.persist_audit();
    }

    /// When a clipboard entry copied now should be cleared.
    fn clipboard_ttl(&self) -> i64 {
        model_now() + self.settings.clipboard_clear_seconds.max(1) as i64
    }

    /// The identity used for clipboard copies.
    ///
    /// Clipboard operations have no pipe caller, so the vault acts on its own
    /// behalf — but it still has to satisfy the grant check, so the owner UI
    /// must hold a grant for the entry it copies. That is deliberate friction:
    /// copying a key out is a release of the secret, and it should look like
    /// one.
    fn clipboard_identity(&self) -> Result<ClientIdentity> {
        self.owner_identity
            .clone()
            .ok_or_else(|| Error::denied(DenyReason::NoGrant, "no owner identity is known"))
    }

    /// Write an encrypted backup. Returns the path written.
    pub fn backup_export(&mut self, path: &str, passphrase: &[u8]) -> Result<String> {
        self.session.deny_if_locked()?;
        if path.trim().is_empty() {
            return Err(Error::invalid("path", "must not be empty"));
        }
        if passphrase.is_empty() {
            return Err(Error::invalid("passphrase", "must not be empty"));
        }
        let dek = self.session.require_dek()?;
        let bytes = crate::backup::export(&self.store, dek, passphrase, self.audit.events())?;
        let p = std::path::Path::new(path);
        crate::storage::atomic::write_atomic(p, &bytes)?;
        self.audit.append(
            AuditKind::BackupExported {
                path: path.to_string(),
            },
            None,
        )?;
        self.persist_audit()?;
        Ok(path.to_string())
    }

    /// Import an encrypted backup, verifying it before writing anything.
    pub fn backup_import(
        &mut self,
        path: &str,
        passphrase: &[u8],
        overwrite: bool,
    ) -> Result<crate::backup::ImportReport> {
        self.session.deny_if_locked()?;
        let p = std::path::Path::new(path);
        let bytes = std::fs::read(p).map_err(|e| Error::io("read backup", e))?;
        let dek = self.session.require_dek()?;
        let report = crate::backup::import(&self.store, dek, &bytes, passphrase, overwrite)?;
        self.audit.append(
            AuditKind::BackupImported {
                entries: report.added + report.replaced,
                merged: report.merged,
            },
            None,
        )?;
        self.persist_audit()?;
        Ok(report)
    }

    /// Log an event attributed to a client.
    pub fn record_refusal(&mut self, kind: &AuditKind, client: Option<String>) -> Result<()> {
        self.audit.append(kind.clone(), client)?;
        self.persist_audit()
    }

    /// Log a metadata read. `count` is the number of entries returned, never
    /// their contents.
    pub fn record_metadata_read(&mut self, client_fingerprint: &str, count: usize) -> Result<()> {
        if count == 0 {
            return Ok(());
        }
        self.audit.append(
            AuditKind::MetadataListed,
            Some(client_fingerprint.to_string()),
        )?;
        self.persist_audit()
    }

    /// Wipe the session on process exit.
    ///
    /// Separate from [`Vault::lock`] because shutdown must not write anything
    /// to disk — there is no point flushing an audit entry on the way out, and
    /// an unwritable disk at shutdown should not delay the process.
    pub fn shutdown(&mut self) {
        self.session.shutdown();
        self.pending.clear();
    }

    /// Log a clipboard clear performed by the daemon's deadline thread.
    pub fn note_clipboard_cleared(&mut self, entry_id: &str) {
        let _ = self.audit.append(
            AuditKind::ClipboardCleared {
                entry_id: entry_id.to_string(),
            },
            None,
        );
        let _ = self.persist_audit();
    }
}

fn model_now() -> i64 {
    crate::model::now_unix()
}
