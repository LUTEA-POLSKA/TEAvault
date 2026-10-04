//! Windows-native message boxes for the two failures that happen *before* the
//! webview exists.
//!
//! ## Why not `eprintln!`
//!
//! The app is built with `windows_subsystem = "windows"`, so it has no console.
//! That is the right trade: a credential manager that flashes a black console
//! window on every launch from the tray reads as a developer build. The cost is
//! that `eprintln!` output goes nowhere, and two failures here used to be
//! silent:
//!
//! - another UI process already holds the single-instance mutex
//! - `teavaultd` is not running, so there is nothing to talk to
//!
//! Both leave the user looking at a window that does nothing. A message box is
//! the only UI available before the webview loads, so that is what these use.
//!
//! Windows is the only supported platform, so this is not behind a `cfg`.

use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, MB_ICONERROR, MB_OK, MB_SETFOREGROUND, MB_TOPMOST, MESSAGEBOX_STYLE,
};
use windows::core::PCWSTR;

/// Show a modal error box.
///
/// `owner` should be the app window where one exists, so the box is centred on
/// it and stays in front; pass `None` during startup, before any window does.
///
/// Failure to display the box is not itself worth reporting — a message box that
/// cannot open would have to be reported by a message box. `debug_assert` keeps
/// the text reachable under a debugger or a log collector.
pub fn error(owner: Option<isize>, title: &str, body: &str) {
    let wide_title: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_body: Vec<u16> = body.encode_utf16().chain(std::iter::once(0)).collect();

    let style: MESSAGEBOX_STYLE = MB_OK | MB_ICONERROR | MB_TOPMOST | MB_SETFOREGROUND;

    let hwnd = owner.map_or(HWND(std::ptr::null_mut()), |h| HWND(h as *mut _));

    // SAFETY: both buffers are NUL-terminated and live for the whole call, and
    // the owner handle is either the real window or null, which Win32 accepts.
    let result = unsafe {
        MessageBoxW(
            Some(hwnd),
            PCWSTR(wide_body.as_ptr()),
            PCWSTR(wide_title.as_ptr()),
            style,
        )
    };

    debug_assert!(result.0 != 0, "MessageBoxW failed to display: {title}: {body}");
}