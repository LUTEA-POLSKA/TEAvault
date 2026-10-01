//! The encrypted vault on disk.
//!
//! ## Layout
//!
//! ```json
//! {
//!   "format_version": 1,
//!   "index":   { "nonce": "...", "ciphertext": "..." },
//!   "secrets": [ { "entry_id": "...", "sealed": { ... } } ]
//! }
//! ```
//!
//! The index — entry metadata plus the whole grant set — is sealed as **one**
//! blob. That is a deliberate choice, and the reason is a privacy one: if
//! metadata were stored in the clear so that a locked vault could still answer
//! `list`, then every process on the machine would learn which providers the
//! user has keys for and how many. The inventory is itself sensitive, so it is
//! encrypted, and `list` requires an unlocked vault. What `list` returns once
//! unlocked still never contains a secret value.
//!
//! Each secret is a separate sealed blob, keyed to its entry id as associated
//! data. So releasing one key decrypts one key: reading the list does not
//! decrypt every secret, and a ciphertext cannot be moved to another entry.
//!
//! ## Failure policy
//!
//! Every read verifies authentication before returning anything. A failure is
//! `Error::Integrity` and there is no partial-decode path, no "recovered" mode
//! and no fallback to the last known good copy.

pub mod atomic;

use serde::{Deserialize, Serialize};

use crate::{
    crypto::{
        aead::{self, Sealed},
        secret::{SecretBytes, SecretString},
    },
    error::{Error, Result},
    model::{ApiKeyMetadata, GrantSet, StoredSecret},
    paths::VaultPaths,
};
use atomic::VaultLock;

/// Associated data for the sealed index. Distinguishes the index from every
/// other blob sealed under the same data key.
pub const INDEX_AAD: &[u8] = b"teavault:v1:vault:index";

/// Associated data for a secret, bound to its entry id.
///
/// The id is part of the authenticated data, so moving entry A's ciphertext
/// into entry B's slot fails to verify.
pub fn secret_aad(entry_id: &str) -> Result<Vec<u8>> {
    if entry_id.is_empty() {
        return Err(Error::invalid("entry_id", "must not be empty"));
    }
    Ok(format!("teavault:v1:vault:secret:{entry_id}").into_bytes())
}

/// The decrypted contents of the index blob.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultIndex {
    #[serde(default)]
    pub entries: Vec<ApiKeyMetadata>,
    #[serde(default)]
    pub grants: GrantSet,
}

/// The whole encrypted vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultData {
    pub format_version: u32,
    /// Sealed [`VaultIndex`].
    pub index: Sealed,
    /// One sealed blob per entry. Never contains the index.
    #[serde(default)]
    pub secrets: Vec<StoredSecret>,
}

/// Reads and writes [`VaultData`]. Owns no key material beyond the data key it
/// is handed per call, and holds none between calls.
pub struct VaultStore {
    paths: VaultPaths,
}

impl VaultStore {
    pub fn new(paths: VaultPaths) -> Self {
        Self { paths }
    }

    pub fn paths(&self) -> &VaultPaths {
        &self.paths
    }

    /// Read the sealed container. Does not decrypt anything.
    pub fn read_raw(&self) -> Result<VaultData> {
        let bytes = crate::storage::atomic::read_optional(&self.paths.data())?
            .ok_or(Error::NotInitialized)?;
        let data: VaultData = serde_json::from_slice(&bytes)?;
        if data.format_version > crate::PROTOCOL_VERSION {
            return Err(Error::UnsupportedFormat {
                found: data.format_version,
                supported: crate::PROTOCOL_VERSION,
            });
        }
        Ok(data)
    }

    /// Write the sealed container atomically, holding the vault lock.
    pub fn write_raw(&self, data: &VaultData) -> Result<()> {
        self.paths.ensure_dir()?;
        let _lock = VaultLock::acquire(&self.paths.lock_file())?;
        let bytes = serde_json::to_vec(data)?;
        crate::storage::atomic::write_atomic(&self.paths.data(), &bytes)
    }

    /// Decrypt the index.
    ///
    /// Takes the data key by reference so the key cannot be dropped out from
    /// under the caller mid-operation.
    pub fn read_index(&self, dek: &SecretBytes) -> Result<VaultIndex> {
        let data = self.read_raw()?;
        let plain = aead::open(dek, INDEX_AAD, &data.index)?;
        let json = plain.as_slice();
        serde_json::from_slice(json).map_err(|_| Error::Integrity)
    }

    /// Write the index, leaving secrets untouched.
    pub fn write_index(&self, dek: &SecretBytes, index: &VaultIndex) -> Result<()> {
        let mut data = self.read_raw()?;
        let json = serde_json::to_vec(index)?;
        data.index = aead::seal(dek, INDEX_AAD, &json)?;
        self.write_raw(&data)
    }

    /// Run a read-modify-write on the index under the vault lock.
    ///
    /// The lock is held across the whole sequence, so two processes editing at
    /// once cannot each write back a version based on the same starting point
    /// and silently lose one of the edits.
    pub fn update_index<T>(
        &self,
        dek: &SecretBytes,
        f: impl FnOnce(&mut VaultIndex) -> Result<T>,
    ) -> Result<T> {
        self.paths.ensure_dir()?;
        let _lock = VaultLock::acquire(&self.paths.lock_file())?;

        let mut data = self.read_raw()?;
        let plain = aead::open(dek, INDEX_AAD, &data.index)?;
        let mut index: VaultIndex =
            serde_json::from_slice(plain.as_slice()).map_err(|_| Error::Integrity)?;

        let out = f(&mut index)?;

        let json = serde_json::to_vec(&index)?;
        data.index = aead::seal(dek, INDEX_AAD, &json)?;
        let bytes = serde_json::to_vec(&data)?;
        crate::storage::atomic::write_atomic(&self.paths.data(), &bytes)?;
        Ok(out)
    }

    /// Seal `secret` and store it against `entry_id`, replacing any previous
    /// value. Does not touch the index, so it is safe to call while adding.
    pub fn put_secret(
        &self,
        dek: &SecretBytes,
        entry_id: &str,
        secret: &SecretString,
    ) -> Result<()> {
        self.paths.ensure_dir()?;
        let _lock = VaultLock::acquire(&self.paths.lock_file())?;

        let mut data = self.read_raw()?;
        let aad = secret_aad(entry_id)?;
        let sealed = aead::seal(dek, &aad, secret.as_bytes())?;
        match data.secrets.iter_mut().find(|s| s.entry_id == entry_id) {
            Some(slot) => slot.sealed = sealed,
            None => data.secrets.push(StoredSecret {
                entry_id: entry_id.to_string(),
                sealed,
            }),
        }
        let bytes = serde_json::to_vec(&data)?;
        crate::storage::atomic::write_atomic(&self.paths.data(), &bytes)
    }

    /// Decrypt exactly one entry's secret.
    ///
    /// This is the only function in the crate that returns plaintext key
    /// material, and it takes the entry id explicitly so the call site has to
    /// have already decided *which* key it is about.
    pub fn get_secret(&self, dek: &SecretBytes, entry_id: &str) -> Result<SecretString> {
        let data = self.read_raw()?;
        let slot = data
            .secrets
            .iter()
            .find(|s| s.entry_id == entry_id)
            .ok_or_else(|| Error::not_found("secret", entry_id))?;
        let plain = aead::open(dek, &secret_aad(entry_id)?, &slot.sealed)?;
        Ok(SecretString::new(plain.into_inner()))
    }

    /// Drop an entry's ciphertext. Used on delete, and on import-merge.
    pub fn remove_secret(&self, entry_id: &str) -> Result<()> {
        self.paths.ensure_dir()?;
        let _lock = VaultLock::acquire(&self.paths.lock_file())?;
        let mut data = self.read_raw()?;
        let before = data.secrets.len();
        data.secrets.retain(|s| s.entry_id != entry_id);
        if data.secrets.len() == before {
            return Ok(());
        }
        let bytes = serde_json::to_vec(&data)?;
        crate::storage::atomic::write_atomic(&self.paths.data(), &bytes)
    }

    /// Whether a ciphertext exists for this entry, without decrypting it.
    pub fn has_secret(&self, entry_id: &str) -> bool {
        self.read_raw()
            .map(|d| d.secrets.iter().any(|s| s.entry_id == entry_id))
            .unwrap_or(false)
    }

    /// An empty vault with a fresh index seal.
    pub fn empty_sealed(dek: &SecretBytes) -> Result<VaultData> {
        let json = serde_json::to_vec(&VaultIndex::default())?;
        Ok(VaultData {
            format_version: crate::PROTOCOL_VERSION,
            index: aead::seal(dek, INDEX_AAD, &json)?,
            secrets: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keyring;

    fn store() -> (tempfile::TempDir, VaultStore, SecretBytes) {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(VaultPaths::new(dir.path()));
        let (_, dek) = Keyring::create(b"passphrase").unwrap();
        store
            .write_raw(&VaultStore::empty_sealed(&dek).unwrap())
            .unwrap();
        (dir, store, dek)
    }

    fn entry(id: &str, name: &str) -> ApiKeyMetadata {
        ApiKeyMetadata {
            id: id.into(),
            name: name.into(),
            display_name: name.into(),
            provider: "OpenAI".into(),
            description: None,
            capabilities: vec!["llm".into()],
            created_at: crate::model::now_rfc3339(),
            updated_at: crate::model::now_rfc3339(),
            visibility: crate::model::Visibility::Discoverable,
        }
    }

    #[test]
    fn a_secret_roundtrips_through_the_store() {
        let (_d, store, dek) = store();
        let value = SecretString::new(b"sk-proj-0123456789abcdef".to_vec());
        store.put_secret(&dek, "entry-1", &value).unwrap();
        assert_eq!(
            store.get_secret(&dek, "entry-1").unwrap().as_bytes(),
            value.as_bytes()
        );
    }

    #[test]
    fn listing_entries_does_not_decrypt_any_secret() {
        // The point of sealing metadata and secrets separately: reading the
        // index must never touch a secret ciphertext.
        let (_d, store, dek) = store();
        store
            .put_secret(&dek, "entry-1", &SecretString::new(b"secret-one".to_vec()))
            .unwrap();
        store
            .put_secret(&dek, "entry-2", &SecretString::new(b"secret-two".to_vec()))
            .unwrap();
        store
            .update_index(&dek, |i| {
                i.entries.push(entry("entry-1", "OPENAI_API_KEY"));
                i.entries.push(entry("entry-2", "GROQ_API_KEY"));
                Ok(())
            })
            .unwrap();

        let index = store.read_index(&dek).unwrap();
        assert_eq!(index.entries.len(), 2);

        // The serialised index must not contain either value.
        let json = serde_json::to_string(&index).unwrap();
        assert!(!json.contains("secret-one"));
        assert!(!json.contains("secret-two"));
    }

    #[test]
    fn a_ciphertext_cannot_be_moved_to_another_entry() {
        // Entry A's ciphertext is authenticated with A's id, so pasting it
        // into B's slot must fail rather than hand back A's value under B's
        // name.
        let (_d, store, dek) = store();
        store
            .put_secret(&dek, "entry-A", &SecretString::new(b"value-A".to_vec()))
            .unwrap();

        let mut data = store.read_raw().unwrap();
        let a = data
            .secrets
            .iter()
            .find(|s| s.entry_id == "entry-A")
            .unwrap()
            .clone();
        data.secrets.push(StoredSecret {
            entry_id: "entry-B".into(),
            sealed: a.sealed,
        });
        store.write_raw(&data).unwrap();

        assert_eq!(
            store.get_secret(&dek, "entry-B").unwrap_err().code(),
            "integrity"
        );
    }

    #[test]
    fn removing_an_entry_deletes_its_ciphertext() {
        let (_d, store, dek) = store();
        store
            .put_secret(&dek, "entry-1", &SecretString::new(b"v".to_vec()))
            .unwrap();
        assert!(store.has_secret("entry-1"));
        store.remove_secret("entry-1").unwrap();
        assert!(!store.has_secret("entry-1"));
        assert_eq!(
            store.get_secret(&dek, "entry-1").unwrap_err().code(),
            "not_found"
        );
    }

    #[test]
    fn a_corrupted_data_file_is_reported_as_integrity_not_silently_accepted() {
        let (_d, store, dek) = store();
        store
            .put_secret(&dek, "entry-1", &SecretString::new(b"v".to_vec()))
            .unwrap();

        let mut data = store.read_raw().unwrap();
        let mut ct = data.index.ciphertext_bytes().unwrap();
        ct[3] ^= 0x08;
        data.index.ciphertext = crate::crypto::hex::encode(&ct);
        store.write_raw(&data).unwrap();

        assert_eq!(store.read_index(&dek).unwrap_err().code(), "integrity");
    }

    #[test]
    fn the_wrong_data_key_cannot_read_the_index() {
        let (_d, store, _dek) = store();
        let (_, other) = Keyring::create(b"a different passphrase").unwrap();
        // AEAD authentication fails, which is `integrity` — the same answer a
        // damaged file gets, because the core cannot tell the two apart and
        // must not try.
        assert_eq!(store.read_index(&other).unwrap_err().code(), "integrity");
    }

    #[test]
    fn reading_a_missing_vault_reports_not_initialized() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(VaultPaths::new(dir.path()));
        assert_eq!(store.read_raw().unwrap_err().code(), "not_initialized");
    }

    #[test]
    fn a_future_format_version_is_refused() {
        let (_d, store, dek) = store();
        let mut data = store.read_raw().unwrap();
        data.format_version = 99;
        store.write_raw(&data).unwrap();
        assert_eq!(store.read_raw().unwrap_err().code(), "unsupported_format");
        // The data key is still valid; the version gate is the refusal.
        let _ = dek;
    }

    #[test]
    fn update_index_persists_across_calls() {
        let (_d, store, dek) = store();
        store
            .update_index(&dek, |i| {
                i.entries.push(entry("e1", "A"));
                Ok(())
            })
            .unwrap();
        store
            .update_index(&dek, |i| {
                i.entries.push(entry("e2", "B"));
                Ok(())
            })
            .unwrap();
        let index = store.read_index(&dek).unwrap();
        assert_eq!(index.entries.len(), 2);
    }

    #[test]
    fn an_empty_entry_id_cannot_be_used_as_associated_data() {
        assert!(secret_aad("").is_err());
    }
}
