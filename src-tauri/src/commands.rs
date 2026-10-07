//! Tauri commands: thin forwards onto the daemon's pipe.
//!
//! Each one is the same shape: build a [`Request`], send it, return the
//! daemon's answer as-is. The one rule these commands obey is that **the
//! daemon's refusal is the answer** — none of them catches an error, retries it,
//! substitutes a default, or falls back to something less strict.
//!
//! Errors cross the IPC boundary as a small serialisable struct rather than as
//! a string, so the frontend can branch on a stable `code` and show a message
//! chosen for that code rather than one parsed out of prose.

use serde::{Deserialize, Serialize};
use teavault_core::ipc::{GrantModeWire, Operation, Request};
use tauri::State;

use crate::SharedClient;
use teavault_daemon::pipe::ClientError;

/// A daemon refusal, as the frontend sees it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandError {
    /// Stable machine-readable code. Branch on this.
    pub code: String,
    /// Human-readable, never secret.
    pub message: String,
    /// Present for `needs_confirmation`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Present for `attempts_exhausted`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u64>,
    pub retryable: bool,
}

/// Send one request. Every command funnels through here.
///
/// One place maps a transport failure onto the frontend shape, so no command can
/// invent its own error handling.
fn forward(
    client: State<'_, SharedClient>,
    id: &str,
    op: Operation,
) -> Result<serde_json::Value, CommandError> {
    client.send(Request::new(id, op)).map_err(from_client_error)
}

/// Turn a pipe error into the shape the frontend sees.
fn from_client_error(e: ClientError) -> CommandError {
    match e {
        ClientError::Refused(r) => CommandError {
            code: r.code,
            message: r.message,
            request_id: r.request_id,
            retry_after_secs: r.retry_after_secs,
            retryable: r.retryable,
        },
        other => CommandError {
            // Not a refusal: the daemon was never asked. The UI shows this as a
            // connection problem rather than as a security decision.
            code: "daemon_unavailable".to_string(),
            message: other.to_string(),
            request_id: None,
            retry_after_secs: None,
            retryable: true,
        },
    }
}

/// Create the vault.
///
/// Owner-tier, like every other administrative operation. The UI goes through
/// this rather than telling the user to open a terminal, because a setup step
/// that lives outside the product is a setup step most people never do.
///
/// The passphrase arrives from the web view. That is the same exposure the
/// unlock field has, and `SECURITY.md` § 5 covers it.
#[tauri::command]
pub fn init(client: State<'_, SharedClient>, passphrase: String) -> Result<serde_json::Value, CommandError> {
    forward(client, "init", Operation::Init { passphrase })
}

#[tauri::command]
pub fn status(client: State<'_, SharedClient>) -> Result<serde_json::Value, CommandError> {
    forward(client, "status", Operation::Status)
}

/// Unlock. The passphrase arrives from the web view, which is a real exposure —
/// see `SECURITY.md` § The web view. It is accepted only because the owner tier
/// is proven by this process's image path, and it is never stored or logged.
#[tauri::command]
pub fn unlock(client: State<'_, SharedClient>, passphrase: String) -> Result<serde_json::Value, CommandError> {
    forward(client, "unlock", Operation::Unlock { passphrase })
}

#[tauri::command]
pub fn lock(client: State<'_, SharedClient>) -> Result<serde_json::Value, CommandError> {
    forward(client, "lock", Operation::Lock)
}

/// Delete the vault and start over. The way out of a forgotten passphrase.
///
/// Owner tier only, and the daemon enforces that: an agent process cannot reach
/// this any more than it can change the passphrase. The UI puts a confirmation in
/// front of it, but the confirmation is there for the user's benefit, not as the
/// control - a web view that skipped it would still be refused nothing extra,
/// because the authority check happens on the far side of the pipe.
#[tauri::command]
pub fn wipe(client: State<'_, SharedClient>) -> Result<serde_json::Value, CommandError> {
    forward(client, "wipe", Operation::Wipe)
}

#[tauri::command]
pub fn list(client: State<'_, SharedClient>, provider: Option<String>) -> Result<serde_json::Value, CommandError> {
    forward(client, "list", Operation::List { provider })
}

#[tauri::command]
pub fn info(client: State<'_, SharedClient>, entry: String) -> Result<serde_json::Value, CommandError> {
    forward(client, "info", Operation::Info { entry })
}

/// Release a secret to *this* process. Goes through the grant check like any
/// other client, so the UI cannot read a key the owner has not granted to it.
#[tauri::command]
pub fn request(
    client: State<'_, SharedClient>,
    entry: String,
    purpose: Option<String>,
) -> Result<serde_json::Value, CommandError> {
    forward(client, "request", Operation::Request { entry, purpose })
}

#[tauri::command]
pub fn approvals(client: State<'_, SharedClient>) -> Result<serde_json::Value, CommandError> {
    forward(client, "approvals", Operation::Approvals)
}

#[tauri::command]
pub fn resolve_approval(
    client: State<'_, SharedClient>,
    request_id: String,
    entry: String,
    mode: GrantModeWire,
) -> Result<serde_json::Value, CommandError> {
    forward(
        client,
        "resolve",
        Operation::Resolve {
            request_id,
            entry,
            mode,
        },
    )
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub fn create_entry(
    client: State<'_, SharedClient>,
    name: String,
    display_name: String,
    provider: String,
    description: Option<String>,
    capabilities: Vec<String>,
    hidden: bool,
    secret: String,
) -> Result<serde_json::Value, CommandError> {
    forward(
        client,
        "create",
        Operation::Create {
            name,
            display_name,
            provider,
            description,
            capabilities,
            hidden,
            secret,
        },
    )
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub fn update_entry(
    client: State<'_, SharedClient>,
    entry: String,
    display_name: String,
    provider: String,
    description: Option<String>,
    capabilities: Vec<String>,
    hidden: bool,
    secret: Option<String>,
) -> Result<serde_json::Value, CommandError> {
    forward(
        client,
        "update",
        Operation::Update {
            entry,
            display_name,
            provider,
            description,
            capabilities,
            hidden,
            secret,
        },
    )
}

#[tauri::command]
pub fn delete_entry(client: State<'_, SharedClient>, entry: String) -> Result<serde_json::Value, CommandError> {
    forward(client, "delete", Operation::Delete { entry })
}

/// Copy to the clipboard. The daemon returns only the masked form, so the value
/// never crosses back into the web view.
#[tauri::command]
pub fn copy(
    client: State<'_, SharedClient>,
    entry: String,
) -> Result<serde_json::Value, CommandError> {
    forward(client, "copy", Operation::Copy { entry })
}

/// Change the master passphrase. Re-wraps the key that protects the vault.
#[tauri::command]
pub fn change_passphrase(
    client: State<'_, SharedClient>,
    current: String,
    new_passphrase: String,
) -> Result<serde_json::Value, CommandError> {
    forward(
        client,
        "change_passphrase",
        Operation::ChangePassphrase {
            current,
            new: new_passphrase,
        },
    )
}

#[tauri::command]
pub fn access_overview(client: State<'_, SharedClient>) -> Result<serde_json::Value, CommandError> {
    forward(client, "access", Operation::Access)
}

#[tauri::command]
pub fn grant(
    client: State<'_, SharedClient>,
    entry: String,
    client_fingerprint: String,
    client_label: String,
    mode: GrantModeWire,
    expires_at: Option<i64>,
) -> Result<serde_json::Value, CommandError> {
    forward(
        client,
        "grant",
        Operation::Grant {
            entry,
            client_fingerprint,
            client_label,
            mode,
            expires_at,
        },
    )
}

#[tauri::command]
pub fn revoke_grant(client: State<'_, SharedClient>, grant_id: String) -> Result<serde_json::Value, CommandError> {
    forward(client, "revoke", Operation::Revoke { grant_id })
}

/// The clients the daemon has actually seen connect.
///
/// This is the *only* list a permission can be created against, which is why it
/// exists as an operation rather than being assembled in the frontend: a
/// compromised UI could offer any fingerprint it liked, and the daemon's refusal
/// is the only thing that stops the grant.
#[tauri::command]
pub fn known_clients(client: State<'_, SharedClient>) -> Result<serde_json::Value, CommandError> {
    forward(client, "known_clients", Operation::KnownClients)
}

#[tauri::command]
pub fn revoke_client(
    client: State<'_, SharedClient>,
    client_fingerprint: String,
) -> Result<serde_json::Value, CommandError> {
    forward(
        client,
        "revoke_client",
        Operation::RevokeClient { client_fingerprint },
    )
}

#[tauri::command]
pub fn get_settings(client: State<'_, SharedClient>) -> Result<serde_json::Value, CommandError> {
    forward(client, "get_settings", Operation::GetSettings)
}

#[tauri::command]
pub fn set_settings(
    client: State<'_, SharedClient>,
    settings: serde_json::Value,
) -> Result<serde_json::Value, CommandError> {
    let parsed: teavault_core::settings::Settings = serde_json::from_value(settings)
        .map_err(|e| CommandError {
            code: "invalid".into(),
            message: format!("the settings could not be read: {:?}", e.classify()),
            request_id: None,
            retry_after_secs: None,
            retryable: false,
        })?;
    forward(client, "set_settings", Operation::SetSettings { settings: parsed })
}

#[tauri::command]
pub fn audit_recent(
    client: State<'_, SharedClient>,
    limit: usize,
) -> Result<serde_json::Value, CommandError> {
    forward(client, "audit", Operation::Audit { limit })
}

#[tauri::command]
pub fn backup_export(
    client: State<'_, SharedClient>,
    path: String,
    passphrase: String,
) -> Result<serde_json::Value, CommandError> {
    forward(
        client,
        "backup_export",
        Operation::BackupExport { path, passphrase },
    )
}

#[tauri::command]
pub fn backup_import(
    client: State<'_, SharedClient>,
    path: String,
    passphrase: String,
    overwrite: bool,
) -> Result<serde_json::Value, CommandError> {
    forward(
        client,
        "backup_import",
        Operation::BackupImport {
            path,
            overwrite,
            passphrase,
        },
    )
}