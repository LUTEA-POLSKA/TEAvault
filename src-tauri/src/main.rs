//! Entry point for the TEAvault desktop UI.
//!
//! The whole application lives in the library so it can be reviewed without a
//! window; this exists only so Cargo has a binary to build.

// Build as a GUI subsystem binary, so Windows shows no console window behind the
// app. A credential manager that flashes a black console every time the user
// opens it from the tray reads as a developer build.
//
// The consequence is that `println!`/`eprintln!` have nowhere to go. The two
// failures that happen before the webview exists — another UI process already
// holding the mutex, and `teavaultd` not running — therefore report through a
// message box instead. See `dialogs.rs` in the library.
#![windows_subsystem = "windows"]

fn main() {
    teavault_app_lib::run()
}