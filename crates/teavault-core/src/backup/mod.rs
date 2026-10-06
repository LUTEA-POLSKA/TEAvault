//! Encrypted backup and restore.
//!
//! ## Rules
//!
//! * **Export is always encrypted.** There is no plaintext export path, not
//!   even a flagged one. A backup that contains plaintext keys is a plaintext
//!   copy of the vault with none of the vault's protections, sitting in a
//!   Documents folder.
//! * **The backup is bound to the passphrase that made it.** Importing without
//!   the right passphrase fails, because the payload is sealed with the key
//!   derived from it. A backup is therefore not a way around the passphrase.
//! * **Integrity is checked before anything is written.** The whole file is
//!   authenticated first; a partially imported vault is not a state this code
//!   can produce.
//! * **Nothing is overwritten by default.** Import merges, and a name collision
//!   keeps the existing entry and skips the incoming one. `overwrite` is an
//!   explicit opt-in.
//!
//! ## What the file contains
//!
//! The encrypted index and every sealed secret, plus the grants, plus the audit
//! log. Grants travel with the backup so that restoring onto a new machine does
//! not silently widen access; the restored owner can revoke them from the
//! access screen. The audit log travels so that the history of the data is not
//! lost with it.

use serde::{Deserialize, Serialize};

use crate::{
    crypto::{
        aead::{self, Sealed},
        kdf::KdfParams,
        secret::SecretBytes,
    },
    error::{Error, Result},
    model::{ApiKeyMetadata, GrantSet},
    storage::{VaultIndex, VaultStore},
};

/// Marker so an import can recognise a TEAvault backup before trying to
/// decrypt it, and so a random file gets a clear message rather than an
/// integrity error.
pub const MAGIC: &str = "TEAVAULT-BACKUP";

/// Associated data for the backup payload.
pub const BACKUP_AAD: &[u8] = b"teavault:v1:backup:payload";

/// The plaintext inside a backup, before sealing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupPayload {
    pub index: VaultIndex,
    /// Sealed secret blobs, copied verbatim. They are already bound to the
    /// original data key, so the backup re-seals them as a whole rather than
    /// decrypting and re-encrypting each one — there is never a moment where
    /// every plaintext key exists in memory at once.
    pub secrets: Vec<crate::model::StoredSecret>,
    /// The audit log, so history travels with the data.
    #[serde(default)]
    pub audit: Vec<crate::audit::AuditEvent>,
    /// When the backup was taken.
    pub created_at: String,
}

/// The file on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupFile {
    pub magic: String,
    pub format_version: u32,
    pub kdf: KdfParams,
    /// Sealed [`BackupPayload`].
    pub payload: Sealed,
    pub created_at: String,
}

/// Outcome of an import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportReport {
    /// Entries copied in.
    pub added: usize,
    /// Entries that already existed and were kept.
    pub skipped: usize,
    /// Entries that replaced an existing entry, only when `overwrite` was set.
    pub replaced: usize,
    /// Grants that came across.
    pub grants: usize,
    /// True when nothing existing was replaced.
    pub merged: bool,
}

/// Build an encrypted backup of the current vault.
///
/// Requires an unlocked vault, because it reads the data key's ciphertext and
/// the audit log. Note it does **not** decrypt any secret: the sealed blobs are
/// copied as they are.
pub fn export(
    store: &VaultStore,
    dek: &SecretBytes,
    passphrase: &[u8],
    audit: &[crate::audit::AuditEvent],
) -> Result<Vec<u8>> {
    let data = store.read_raw()?;
    let index = store.read_index(dek)?;

    let payload = BackupPayload {
        index,
        secrets: data.secrets,
        audit: audit.to_vec(),
        created_at: crate::model::now_rfc3339(),
    };

    // The backup is sealed with a key derived from the passphrase directly,
    // rather than with the vault's data key. That is what binds the backup to
    // the passphrase: a stolen backup plus a running, unlocked TEAvault still
    // does not yield the backup without the passphrase.
    let kdf = KdfParams::generate()?;
    let kek = kdf.derive(passphrase, aead::KEY_LEN)?;
    let json = serde_json::to_vec(&payload)?;
    let sealed = aead::seal(&kek, BACKUP_AAD, &json)?;

    let file = BackupFile {
        magic: MAGIC.to_string(),
        format_version: crate::PROTOCOL_VERSION,
        kdf,
        payload: sealed,
        created_at: payload.created_at,
    };
    Ok(serde_json::to_vec(&file)?)
}

/// Read a backup's header without decrypting the payload.
///
/// Lets the UI show when a backup was taken before asking the user for a
/// passphrase, and lets [`import`] give a clear "this is not a TEAvault backup"
/// message for an unrelated file.
pub fn peek(bytes: &[u8]) -> Result<(BackupFile, bool)> {
    let file: BackupFile = serde_json::from_slice(bytes).map_err(|_| {
        // Any parse failure is reported the same way, whether the file is a
        // text document, a truncated download, or a backup from a build whose
        // fields we do not know. Telling those apart tells an attacker which
        // one they are holding, and none of them has a different recovery.
        Error::invalid("backup", "this file is not a readable TEAvault backup")
    })?;
    if file.magic != MAGIC {
        return Err(Error::invalid(
            "backup",
            "this file is not a TEAvault backup",
        ));
    }
    if file.format_version > crate::PROTOCOL_VERSION {
        return Err(Error::UnsupportedFormat {
            found: file.format_version,
            supported: crate::PROTOCOL_VERSION,
        });
    }
    // `sealed` being well-formed is not the same as the payload verifying;
    // this only says the header parsed.
    let header_ok = file.kdf.validate().is_ok() && file.payload.ciphertext_bytes().is_ok();
    Ok((file, header_ok))
}

/// Import a backup.
///
/// The whole payload is authenticated before a single byte is written, so a
/// corrupt or wrong-passphrase backup cannot leave a half-merged vault.
pub fn import(
    store: &VaultStore,
    dek: &SecretBytes,
    bytes: &[u8],
    passphrase: &[u8],
    overwrite: bool,
) -> Result<ImportReport> {
    let (file, header_ok) = peek(bytes)?;
    if !header_ok {
        return Err(Error::invalid("backup", "the backup header is damaged"));
    }

    // Wrong passphrase and tampered payload are indistinguishable on purpose.
    let kek = file.kdf.derive(passphrase, aead::KEY_LEN)?;
    let plain =
        aead::open(&kek, BACKUP_AAD, &file.payload).map_err(|_| Error::InvalidPassphrase)?;
    let payload: BackupPayload =
        serde_json::from_slice(plain.as_slice()).map_err(|_| Error::InvalidPassphrase)?;

    let index = store.read_index(dek)?;
    let mut report = ImportReport {
        added: 0,
        skipped: 0,
        replaced: 0,
        grants: payload.index.grants.grants.len(),
        merged: !overwrite,
    };

    // Plan the whole merge first, then write it. A plan that fails leaves the
    // vault untouched.
    let mut next_index = index.clone();
    let mut incoming_secrets = Vec::new();

    for entry in &payload.index.entries {
        crate::model::validate_var_name(&entry.name)?;
        match next_index.entries.iter_mut().find(|e| e.name == entry.name) {
            Some(existing) => {
                if overwrite {
                    existing.clone_from(entry);
                    report.replaced += 1;
                    if let Some(s) = payload
                        .secrets
                        .iter()
                        .find(|s| s.entry_id == entry.id)
                        .cloned()
                    {
                        incoming_secrets.push(s);
                    }
                } else {
                    // Never overwrite silently. The owner decides.
                    report.skipped += 1;
                }
            }
            None => {
                next_index.entries.push(entry.clone());
                report.added += 1;
                if let Some(s) = payload
                    .secrets
                    .iter()
                    .find(|s| s.entry_id == entry.id)
                    .cloned()
                {
                    incoming_secrets.push(s);
                } else {
                    return Err(Error::Malformed(
                        "backup references an entry with no ciphertext".into(),
                    ));
                }
            }
        }
    }

    // Grants travel with the data, but never silently widen access: a grant for
    // a client is only useful if that client exists on this machine, and the
    // owner can revoke everything from the access screen.
    for g in payload.index.grants.grants {
        next_index.grants.upsert(g);
    }

    let json = serde_json::to_vec(&next_index)?;
    let mut data = store.read_raw()?;
    data.index = aead::seal(dek, crate::storage::INDEX_AAD, &json)?;
    for s in incoming_secrets {
        match data.secrets.iter_mut().find(|d| d.entry_id == s.entry_id) {
            Some(slot) => slot.sealed = s.sealed,
            None => data.secrets.push(s),
        }
    }
    store.write_raw(&data)?;

    Ok(report)
}

/// Summarise a backup for the UI without a passphrase.
pub fn describe(bytes: &[u8]) -> Result<BackupSummary> {
    let (file, header_ok) = peek(bytes)?;
    Ok(BackupSummary {
        created_at: file.created_at,
        format_version: file.format_version,
        header_intact: header_ok,
        kdf: file.kdf.clone(),
        size_bytes: bytes.len(),
    })
}

/// Non-secret facts about a backup file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupSummary {
    pub created_at: String,
    pub format_version: u32,
    /// Whether the header parses and the KDF parameters are sane. Says nothing
    /// about whether the payload verifies — that needs the passphrase.
    pub header_intact: bool,
    pub kdf: KdfParams,
    pub size_bytes: usize,
}

/// What an entry looks like after import, for the report. No secrets.
pub fn entry_names(payload_index: &VaultIndex) -> Vec<String> {
    payload_index
        .entries
        .iter()
        .map(|e: &ApiKeyMetadata| e.name.clone())
        .collect()
}

/// Whether a grant set came across unchanged, for tests.
pub fn grant_count(gs: &GrantSet) -> usize {
    gs.grants.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::secret::SecretString, model::Visibility, paths::VaultPaths};

    const PASS: &[u8] = b"the backup passphrase";

    fn vault() -> (tempfile::TempDir, VaultStore, SecretBytes) {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(VaultPaths::new(dir.path()));
        let dek = crate::crypto::aead::generate_data_key().unwrap();
        store
            .write_raw(&VaultStore::empty_sealed(&dek).unwrap())
            .unwrap();
        (dir, store, dek)
    }

    fn add(store: &VaultStore, dek: &SecretBytes, name: &str, value: &str) -> String {
        let id = format!("id-{name}");
        let entry = ApiKeyMetadata {
            id: id.clone(),
            name: name.into(),
            display_name: name.into(),
            provider: "OpenAI".into(),
            description: None,
            capabilities: vec!["llm".into()],
            created_at: crate::model::now_rfc3339(),
            updated_at: crate::model::now_rfc3339(),
            visibility: Visibility::Discoverable,
            category: None,
        };
        store
            .update_index(dek, |ix| {
                ix.entries.push(entry);
                Ok(())
            })
            .unwrap();
        store
            .put_secret(dek, &id, &SecretString::new(value.as_bytes().to_vec()))
            .unwrap();
        id
    }

    #[test]
    fn a_backup_contains_no_plaintext_secret() {
        let (_d, store, dek) = vault();
        add(&store, &dek, "OPENAI_API_KEY", "sk-plaintext-marker-value");
        let bytes = export(&store, &dek, PASS, &[]).unwrap();

        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("sk-plaintext-marker-value"));
        assert!(
            !text.contains("OPENAI_API_KEY"),
            "names must be encrypted too"
        );
        assert!(text.contains(MAGIC), "the marker must be readable");
    }

    #[test]
    fn export_import_roundtrips_every_secret() {
        let (_d, store, dek) = vault();
        add(&store, &dek, "A", "value-a");
        add(&store, &dek, "B", "value-b");
        let bytes = export(&store, &dek, PASS, &[]).unwrap();

        let dir2 = tempfile::tempdir().unwrap();
        let store2 = VaultStore::new(VaultPaths::new(dir2.path()));
        store2
            .write_raw(&VaultStore::empty_sealed(&dek).unwrap())
            .unwrap();

        let report = import(&store2, &dek, &bytes, PASS, false).unwrap();
        assert_eq!(report.added, 2);
        assert_eq!(
            store2.get_secret(&dek, "id-A").unwrap().as_bytes(),
            b"value-a"
        );
        assert_eq!(
            store2.get_secret(&dek, "id-B").unwrap().as_bytes(),
            b"value-b"
        );
    }

    #[test]
    fn import_refuses_the_wrong_passphrase_and_writes_nothing() {
        let (_d, store, dek) = vault();
        add(&store, &dek, "A", "value-a");
        let bytes = export(&store, &dek, PASS, &[]).unwrap();

        let dir2 = tempfile::tempdir().unwrap();
        let store2 = VaultStore::new(VaultPaths::new(dir2.path()));
        store2
            .write_raw(&VaultStore::empty_sealed(&dek).unwrap())
            .unwrap();

        let err = import(&store2, &dek, &bytes, b"wrong passphrase", false).unwrap_err();
        assert_eq!(err.code(), "invalid_passphrase");
        assert_eq!(
            store2.read_index(&dek).unwrap().entries.len(),
            0,
            "a refused import must leave the vault untouched"
        );
    }

    #[test]
    fn import_does_not_overwrite_by_default() {
        let (_d, store, dek) = vault();
        add(&store, &dek, "A", "from-backup");
        let bytes = export(&store, &dek, PASS, &[]).unwrap();

        // A destination that already has A with a different value.
        let dir2 = tempfile::tempdir().unwrap();
        let store2 = VaultStore::new(VaultPaths::new(dir2.path()));
        store2
            .write_raw(&VaultStore::empty_sealed(&dek).unwrap())
            .unwrap();
        add(&store2, &dek, "A", "already-here");
        add(&store2, &dek, "C", "local-only");

        let report = import(&store2, &dek, &bytes, PASS, false).unwrap();
        assert_eq!(report.skipped, 1, "the existing entry must be kept");
        assert_eq!(report.added, 0);
        assert_eq!(
            store2.get_secret(&dek, "id-A").unwrap().as_bytes(),
            b"already-here",
            "an existing secret must survive a merge"
        );
        assert_eq!(store2.read_index(&dek).unwrap().entries.len(), 2);
    }

    #[test]
    fn overwrite_replaces_only_when_asked() {
        let (_d, store, dek) = vault();
        add(&store, &dek, "A", "from-backup");
        let bytes = export(&store, &dek, PASS, &[]).unwrap();

        let dir2 = tempfile::tempdir().unwrap();
        let store2 = VaultStore::new(VaultPaths::new(dir2.path()));
        store2
            .write_raw(&VaultStore::empty_sealed(&dek).unwrap())
            .unwrap();
        add(&store2, &dek, "A", "already-here");

        let report = import(&store2, &dek, &bytes, PASS, true).unwrap();
        assert_eq!(report.replaced, 1);
        assert_eq!(
            store2.get_secret(&dek, "id-A").unwrap().as_bytes(),
            b"from-backup"
        );
    }

    #[test]
    fn a_tampered_backup_is_refused() {
        let (_d, store, dek) = vault();
        add(&store, &dek, "A", "value-a");
        let mut bytes = export(&store, &dek, PASS, &[]).unwrap();

        // Flip a byte in the middle of the sealed payload.
        let i = bytes.len() / 2;
        bytes[i] ^= 0x01;

        let dir2 = tempfile::tempdir().unwrap();
        let store2 = VaultStore::new(VaultPaths::new(dir2.path()));
        store2
            .write_raw(&VaultStore::empty_sealed(&dek).unwrap())
            .unwrap();
        assert!(import(&store2, &dek, &bytes, PASS, false).is_err());
        assert_eq!(store2.read_index(&dek).unwrap().entries.len(), 0);
    }

    #[test]
    fn an_unrelated_file_is_rejected_with_a_clear_message() {
        assert_eq!(peek(b"just a text file").unwrap_err().code(), "invalid");
        assert_eq!(describe(b"{}").unwrap_err().code(), "invalid");
    }

    #[test]
    fn describe_works_without_a_passphrase() {
        let (_d, store, dek) = vault();
        add(&store, &dek, "A", "value-a");
        let bytes = export(&store, &dek, PASS, &[]).unwrap();
        let s = describe(&bytes).unwrap();
        assert!(s.header_intact);
        assert_eq!(s.format_version, crate::PROTOCOL_VERSION);
        assert_eq!(s.size_bytes, bytes.len());
    }

    #[test]
    fn a_future_backup_version_is_refused_before_the_passphrase_is_needed() {
        let (_d, store, dek) = vault();
        add(&store, &dek, "A", "value-a");
        let mut file: BackupFile =
            serde_json::from_slice(&export(&store, &dek, PASS, &[]).unwrap()).unwrap();
        file.format_version = 99;
        let bytes = serde_json::to_vec(&file).unwrap();
        assert_eq!(peek(&bytes).unwrap_err().code(), "unsupported_format");
    }

    #[test]
    fn a_downgraded_kdf_in_a_backup_is_refused() {
        let (_d, store, dek) = vault();
        add(&store, &dek, "A", "value-a");
        let mut file: BackupFile =
            serde_json::from_slice(&export(&store, &dek, PASS, &[]).unwrap()).unwrap();
        file.kdf.m_cost_kib = 1;
        let bytes = serde_json::to_vec(&file).unwrap();
        // The header parses, but the parameters are rejected as not intact, and
        // the import refuses.
        let (_, ok) = peek(&bytes).unwrap();
        assert!(!ok);
        let err = import(&store, &dek, &bytes, PASS, false).unwrap_err();
        assert_eq!(err.code(), "invalid");
    }

    #[test]
    fn grants_travel_with_the_backup_and_can_be_inspected_afterwards() {
        use crate::model::grant::{Grant, GrantMode};

        let (_d, store, dek) = vault();
        let id = add(&store, &dek, "A", "value-a");
        store
            .update_index(&dek, |ix| {
                ix.grants.upsert(Grant::new(
                    "fp|app.exe",
                    "app.exe",
                    id.clone(),
                    GrantMode::AlwaysAllow { expires_at: None },
                ));
                Ok(())
            })
            .unwrap();

        let bytes = export(&store, &dek, PASS, &[]).unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        let store2 = VaultStore::new(VaultPaths::new(dir2.path()));
        store2
            .write_raw(&VaultStore::empty_sealed(&dek).unwrap())
            .unwrap();
        let report = import(&store2, &dek, &bytes, PASS, false).unwrap();
        assert_eq!(report.grants, 1);
        assert_eq!(grant_count(&store2.read_index(&dek).unwrap().grants), 1);
    }

    #[test]
    fn the_audit_log_travels_with_the_backup() {
        let (_d, store, dek) = vault();
        add(&store, &dek, "A", "value-a");
        let mut log = crate::audit::AuditLog::new();
        log.append(crate::audit::AuditKind::VaultUnlocked, None)
            .unwrap();
        let bytes = export(&store, &dek, PASS, log.events()).unwrap();

        let file: BackupFile = serde_json::from_slice(&bytes).unwrap();
        let kek = file.kdf.derive(PASS, aead::KEY_LEN).unwrap();
        let plain = aead::open(&kek, BACKUP_AAD, &file.payload).unwrap();
        let payload: BackupPayload = serde_json::from_slice(plain.as_slice()).unwrap();
        assert_eq!(payload.audit.len(), 1);
    }
}
