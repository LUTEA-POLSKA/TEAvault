//! The TEAvault desktop UI, as a Tauri shell.
//!
//! ## This crate holds no authority over the vault
//!
//! Every command below forwards a request to `teavaultd` over the named pipe and
//! returns whatever the daemon decides. There is no crypto here, no permission
//! check here, and no path by which the web view reaches a secret except the
//! daemon's `request` operation — which applies the same grant check it applies
//! to the CLI and to any other local client.
//!
//! If the UI owned the vault, every XSS or dependency compromise in the frontend
//! would be a key compromise. Here it is an inconvenience at worst, because the
//! frontend is a *client* of a policy engine that does not know it exists.
//!
//! ## What the UI *is* trusted with
//!
//! The UI is in the **owner tier**: its image path is one of the two binaries the
//! daemon expects next to itself, and that is what lets it create and edit keys,
//! manage grants, change the passphrase and write backups. So the honest statement
//! is not "the UI has no authority" but:
//!
//! > The UI is a trusted owner client. The daemon does not trust anything the
//! > frontend *says* — it re-derives the identity from the pipe handle — and it
//! > refuses every operation a grant cannot authorise. What the UI can do is
//! > bounded by that tier, and two places inside the tier are additionally
//! > constrained in the daemon, not in the frontend:
//!
//! * a **grant** can only be created for a client the daemon has actually seen
//!   connect, with the label the daemon recorded rather than one the caller
//!   supplied;
//! * **secret release** always goes through `request`, so even the owner UI
//!   cannot read a key without a grant — the same rule an agent faces.
//!
//! A compromised owner UI can therefore still create and delete keys and change
//! settings. That is a deliberate trade: those are exactly the actions the UI
//! exists for, and the alternative — a UI that could not manage its own vault —
//! would move the authority into the daemon's own UI, which is a larger program
//! with a browser engine in it, not a smaller one.
//!
//! ## The window is on demand
//!
//! Closing the window **ends this process**. The daemon and the tray keep running,
//! which is what the low-idle goal actually requires: an open WebView2 is one of
//! the most expensive things TEAvault owns, and there is no reason to keep one
//! resident for a window nobody is looking at.
//!
//! The tray lives in the daemon only. Two tray icons — one per process — is a bug
//! that looks like a feature, and it made "quit" ambiguous. A single named mutex
//! means at most one UI process exists, and launching again focuses the existing
//! window rather than opening a second one.

mod commands;
mod dialogs;
mod fixed_size;
mod single_instance;

use std::sync::Mutex;

use tauri::Manager;

use teavault_daemon::pipe::Client;

/// A pipe client behind Tauri's managed state.
///
/// Two things force this wrapper. Tauri's `State<T>` requires `Send + Sync`, and
/// a raw `HANDLE` is neither. And `Client::send` writes a request and reads a
/// response on the same handle, so two concurrent invocations would interleave
/// on the wire — the mutex serialises them, which also makes the safety claim
/// true rather than merely plausible: at most one thread is inside `send` at a
/// time.
///
/// The handle is a kernel object for a named pipe; sharing the *handle* across
/// threads is safe. What is not safe is using it concurrently, and the mutex is
/// what prevents that.
pub struct SharedClient(Mutex<Client>);

// SAFETY: see the type-level comment. `send` is only reachable with the mutex
// held, so no two threads touch the handle at once.
unsafe impl Send for SharedClient {}
unsafe impl Sync for SharedClient {}

impl SharedClient {
    pub fn send(
        &self,
        req: teavault_core::ipc::Request,
    ) -> Result<serde_json::Value, teavault_daemon::pipe::ClientError> {
        let guard = self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.send(req)
    }
}

/// Build and run the desktop UI.
///
/// A thin `main` so the whole app lives in the library: that is what lets the
/// crate be checked, reviewed and reasoned about without a window.
pub fn run() {
    // A second UI process would be a second WebView, a second pipe session and a
    // second set of windows, with no way for the user to tell. The mutex is
    // released when this process exits, so the next launch is free.
    let _instance = match single_instance::acquire("TEAvaultUi-v1") {
        Ok(handle) => handle,
        Err(e) => {
            dialogs::error(
                None,
                "TEAvault is already open",
                &format!("{e}\n\nThe existing window is already showing your vault."),
            );
            std::process::exit(0);
        }
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::status,
            commands::init,
            commands::unlock,
            commands::lock,
            commands::wipe,
            commands::list,
            commands::info,
            commands::request,
            commands::approvals,
            commands::resolve_approval,
            commands::create_entry,
            commands::update_entry,
            commands::delete_entry,
            commands::copy_to_clipboard,
            commands::access_overview,
            commands::grant,
            commands::revoke_grant,
            commands::revoke_client,
            commands::known_clients,
            commands::get_settings,
            commands::set_settings,
            commands::audit_recent,
            commands::backup_export,
            commands::backup_import,
        ])
        .setup(|app| {
            // Connect once, here. The UI holds a client for its lifetime, so a
            // request does not pay for a fresh connection each time — and if the
            // daemon is not running, that is a startup problem worth reporting
            // rather than a per-click error.
            match Client::connect_with_retry(std::time::Duration::from_secs(2)) {
                Ok(c) => {
                    app.manage(SharedClient(Mutex::new(c)));
                }
                Err(e) => {
                    // A startup blocker, so it gets a real window rather than a
                    // line on a console this build does not have. The UI is
                    // closed afterwards: with no daemon there is nothing it can
                    // do, and an inert window is a worse answer than none.
                    dialogs::error(
                        None,
                        "TEAvault cannot reach its background process",
                        &format!(
                            "{e}\n\nStart it and try again:\n\n    teavaultd.exe"
                        ),
                    );
                    app.handle().exit(0);
                }
            }
            fixed_size::apply(app.handle());
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                // Exiting, not hiding. The daemon and its tray outlive this
                // process, and the WebView2 instance — by far the most expensive
                // resource TEAvault owns — goes with it. Closing the window is
                // what the user meant.
                //
                // The close is not prevented, so the default teardown runs and
                // `Drop` for the pipe client closes the handle.
                let app = window.app_handle().clone();
                window.close().ok();
                std::thread::spawn(move || {
                    // Give the close event a moment to finish tearing the web
                    // view down before asking the process to exit.
                    std::thread::sleep(std::time::Duration::from_millis(120));
                    app.exit(0);
                });
            }
        })
        .run(tauri::generate_context!())
        .expect("the TEAvault UI must start");
}