//! The TEAvault desktop UI, as a Tauri shell.
//!
//! ## This crate holds no authority
//!
//! Every command below forwards a request to `teavaultd` over the named pipe and
//! returns whatever the daemon decides. There is no crypto here, no permission
//! check here, and no path by which the web view reaches a secret except the
//! daemon's `request` operation — which applies the same grant check it applies
//! to the CLI and to any other local client.
//!
//! That is the point of the split. If the UI owned the vault, every XSS or
//! dependency compromise in the frontend would be a key compromise. Here it is
//! an inconvenience at worst, because the frontend is a *client* of a policy
//! engine that does not know it exists.
//!
//! ## The window
//!
//! Closing the window hides it; the daemon and the tray keep running. The
//! web view is destroyed with the window, so nothing keeps a browser engine
//! resident when the UI is closed — that is the low-idle requirement, and it is
//! why this is a separate process from the daemon rather than a mode of it.

mod commands;
mod fixed_size;

use std::sync::Mutex;

use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager,
};

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

/// The tray menu labels, mirrored from the daemon's tray.
const M_OPEN: &str = "Open TEAvault";
const M_LOCK: &str = "Lock now";
const M_SETTINGS: &str = "Settings";
const M_QUIT: &str = "Quit TEAvault";

/// Build and run the desktop UI.
///
/// A thin `main` so the whole app lives in the library: that is what lets the
/// crate be checked, reviewed and reasoned about without a window.
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::status,
            commands::init,
            commands::unlock,
            commands::lock,
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
                    eprintln!("teavault: {e}");
                    eprintln!("teavault: start the background process with `teavaultd`.");
                }
            }
            build_tray(app.handle())?;
            fixed_size::apply(app.handle());
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // Hiding, not closing: the daemon and tray must outlive the
                // window. Quitting is an explicit tray action.
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("the TEAvault UI must start");
}

fn build_tray(app: &tauri::AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", M_OPEN, true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "lock", M_LOCK, true, None::<&str>)?;
    let settings = MenuItem::with_id(app, "settings", M_SETTINGS, true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", M_QUIT, true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &lock, &settings, &quit])?;

    TrayIconBuilder::with_id("teavault")
        .menu(&menu)
        .tooltip("TEAvault")
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" | "settings" => show_window(app),
            "lock" => {
                // The daemon owns the session, so locking is a message it sends
                // rather than something the UI does to itself. If the daemon is
                // not running there is nothing to lock.
                if let Some(client) = app.try_state::<SharedClient>() {
                    let _ = client.send(teavault_core::ipc::Request::new(
                        "lock",
                        teavault_core::ipc::Operation::Lock,
                    ));
                }
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_window(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

/// Bring the main window forward, creating nothing.
///
/// Used by the tray's Open action. The window is created eagerly at startup and
/// hidden only on close, so this is a show + focus rather than a create — which
/// is what keeps the WebView alive between openings instead of paying to
/// rebuild it every time.
fn show_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}