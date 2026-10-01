//! `teavaultd` — the TEAvault background process.
//!
//! Owns the vault, the tray and the named pipe. No web view, no network, no
//! telemetry, no timer thread.
//!
//! ## Threads
//!
//! Three, and each exists for a reason a simpler design would not survive:
//!
//! | thread | why it must be separate |
//! |---|---|
//! | main | runs the tray message pump; `GetMessage` blocks and cannot also wait on a pipe |
//! | pipe | `ConnectNamedPipe` blocks; the tray must stay live while it waits |
//! | deadline | parked on a condvar until a clipboard clear is due — alive only between a copy and its deadline |
//!
//! None of them polls. A pipe read blocks in the kernel, a tray click arrives as
//! a window message, and the deadline thread sleeps until signalled or timed out.
//! Measured numbers are in `BENCHMARKS.md`; they are measurements, not guarantees.
//!
//! ## What it deliberately does not do
//!
//! * **No privileged service.** It runs as the user, in the user session. A
//!   SYSTEM service could read keys with no user present, which is a capability
//!   this product has no use for.
//! * **No auto-unlock at login.** The vault comes up locked every time,
//!   including after a reboot.
//! * **No periodic scan of the vault.** It is read only when a request needs it.
//! * **No web view.** The UI is a separate process, started on demand.

use std::{path::PathBuf, sync::Arc};

use teavault_core::{
    clipboard::Clipboard, ipc::OwnerCheck, model::ClientIdentity, paths::VaultPaths, Vault,
};

use teavault_daemon::{
    clipboard::WindowsClipboard,
    server::{serve_forever, spawn_deadline_thread, Shared},
    tray::{Pump, Tray, TrayAction},
};

/// Binaries allowed to reach the owner tier, all expected in the directory the
/// daemon itself lives in.
///
/// Both are owner tools: the UI is how the vault is managed by hand, and the CLI
/// is how it is created and unlocked in the first place. A list rather than one
/// name because omitting the CLI would make `teavault init` — the first command
/// in the README — fail for lack of privilege.
const OWNER_EXES: &[&str] = &["teavault-app.exe", "teavault.exe"];

/// The binary the tray launches when asked to open the UI.
const UI_EXE: &str = "teavault-app.exe";

fn main() {
    if let Err(e) = run() {
        eprintln!("teavaultd: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let owner = Arc::new(OwnerCheck::from_exe_paths(&exe, OWNER_EXES));

    let _instance = SingleInstance::acquire()?;

    let mut vault = Vault::open(VaultPaths::user_default())
        .map_err(|e| format!("opening the vault failed: {e}"))?;

    // The clipboard and the identity a copy acts under are set once, here.
    // A copy still has to pass the grant check, and doing it under the daemon's
    // own verified identity is what makes that check meaningful.
    let clipboard: Arc<dyn Clipboard> = Arc::new(WindowsClipboard);
    vault.set_clipboard(Box::new(WindowsClipboard));
    vault.set_owner_identity(ClientIdentity::new(
        std::process::id(),
        exe.to_string_lossy().to_string(),
    ));

    println!("TEAvault daemon");
    println!("  vault:    {}", vault.paths().display());
    println!("  pipe:     {}", teavault_daemon::pipe::PIPE_NAME);
    println!("  owner:    {}", owner.expected_paths().join(", "));
    println!("  kdf:      {}", vault.cost_summary());
    println!(
        "  state:    {}",
        if vault.is_unlocked() {
            "unlocked"
        } else {
            "locked"
        }
    );
    if !vault.is_initialized() {
        println!("  note:     no vault yet — the app will offer to create one");
    }

    let shared = Arc::new(Shared::new(vault, owner, clipboard));
    let tray = Tray::new("TEAvault")?;

    let deadline = spawn_deadline_thread(Arc::clone(&shared));
    let pipe = serve_forever(
        Arc::clone(&shared),
        std::process::id(),
        exe.to_string_lossy().to_string(),
    );

    // The tray owns the main thread; everything the user does by hand arrives
    // here as a message.
    let result = tray.pump(|action| handle_tray_action(action, &shared, &tray));

    shared.quit();
    if let Ok(mut v) = shared.vault.lock() {
        v.shutdown();
    }

    let _ = deadline.join();
    let _ = pipe.join();

    match result {
        Ok(Pump::Quit) => {
            println!("  shutting down");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn handle_tray_action(action: TrayAction, shared: &Arc<Shared>, tray: &Tray) {
    match action {
        // All three need the window; letting the UI decide which screen to open
        // is one less thing to keep in sync between two processes.
        TrayAction::Open | TrayAction::Recent | TrayAction::Settings => open_ui(),
        TrayAction::LockNow => {
            shared.with_vault(|v| {
                let _ = v.lock();
            });
            tray.set_tip("TEAvault — locked");
        }
        TrayAction::Quit => shared.quit(),
    }
}

/// Spawn the UI on demand.
///
/// Only the binary next to this executable is ever started, so nothing dropped
/// elsewhere on disk can be launched by the tray.
fn open_ui() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let Some(dir) = exe.parent() else { return };
    let ui = dir.join(UI_EXE);
    if !ui.exists() {
        eprintln!(
            "  the UI binary is not installed next to teavaultd: {}",
            ui.display()
        );
        return;
    }
    let _ = std::process::Command::new(ui).spawn();
}

/// A named mutex, so a second daemon refuses to start.
struct SingleInstance(*mut std::ffi::c_void);

impl SingleInstance {
    fn acquire() -> Result<Self, String> {
        use windows::Win32::{
            Foundation::{GetLastError, ERROR_ALREADY_EXISTS},
            System::Threading::CreateMutexW,
        };
        unsafe {
            let name: Vec<u16> = "Local\\TEAvaultDaemon-v1"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let handle = CreateMutexW(None, true, windows::core::PCWSTR(name.as_ptr()))
                .map_err(|e| format!("could not create the instance mutex: {e}"))?;
            // `GetLastError` must be read immediately; any other call resets it.
            if GetLastError() == ERROR_ALREADY_EXISTS {
                let _ = windows::Win32::Foundation::CloseHandle(handle);
                return Err("another teavaultd is already running".into());
            }
            Ok(Self(handle.0))
        }
    }
}

impl Drop for SingleInstance {
    fn drop(&mut self) {
        unsafe {
            let _ =
                windows::Win32::Foundation::CloseHandle(windows::Win32::Foundation::HANDLE(self.0));
        }
    }
}

/// Unused on purpose: the daemon never opens a network listener. Present so the
/// intent is greppable if someone adds one later.
#[allow(dead_code)]
fn no_network_listener() -> ! {
    unimplemented!("TEAvault is a local-only, named-pipe product")
}

#[allow(dead_code)]
fn _type_check(_: PathBuf) {}
