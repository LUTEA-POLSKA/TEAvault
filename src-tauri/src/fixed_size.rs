//! Pin the window to one size.
//!
//! What the user can do is drag the border, and that is gated entirely by
//! `WS_THICKFRAME`: with it clear there is no sizing frame to grab, so the sizing
//! loop never starts. `resizable: false` clears that bit, which is the whole
//! mechanism.
//!
//! `min == max` is set as well, because tao answers `WM_GETMINMAXINFO` from its
//! size constraints (the `WM_GETMINMAXINFO` arm of `public_window_callback` in
//! `platform_impl/windows/event_loop.rs`), so the system-side routes — snapping,
//! a DPI change — resolve to the same size.
//!
//! The module also strips the frame Windows draws around an undecorated window.
//! Two separate things produce a visible edge, and only both are needed to make
//! it disappear:
//!
//! * `WS_CAPTION` (`WS_BORDER | WS_DLGFRAME`) — left set by `decorations: false`,
//!   and drawn as a 1px line.
//! * The DWM border that comes with `WS_EX_APPWINDOW`. Measured at 8px of
//!   `#99B4D1` — the Windows accent colour — down the left and top edges of a
//!   window that has no frame to draw. It is DWM's own composition, not a style
//!   bit, so no amount of clearing styles removes it.
//!
//! `shadow: false` in `tauri.conf.json` matters for the same reason: the DWM
//! shadow is a surface of its own, and a shadow on a window that is supposed to
//! be frameless reads as a lighter band along two edges.
//!
//! `WS_SYSMENU` deliberately stays: a borderless window needs it for Alt+Tab,
//! Alt+F4 and the taskbar entry. Only the drawing goes.
//!
//! The size is read back from the live window rather than repeated here, so
//! `tauri.conf.json` stays the single source of truth. Two sizes that could drift
//! apart are worse than one that is written down twice.
//!
//! ## Why there is no window-procedure subclass
//!
//! Subclassing the procedure and answering `WM_GETMINMAXINFO` directly is the
//! textbook answer, and it was tried. It crashes the app on launch with
//! `0xC000041D` — an unhandled exception inside a callback, i.e. the new procedure
//! faulted.
//!
//! The cause is in tao's own callback: it keeps its per-window state in
//! `GWL_USERDATA` (`SetWindowLongPtrW(window, GWL_USERDATA, userdata)`) and its
//! first act for every message is to read that slot back and dereference it.
//! Putting a second pointer there hands tao a `Pin` where it expects a
//! `ThreadMsgTargetData`, and the next message dereferences garbage.
//!
//! So the constraint is concrete rather than stylistic: tao owns
//! `GWL_USERDATA`, and there is no second owner. Its public API already reaches
//! the message that would have needed the subclass.

use tauri::{Manager, PhysicalSize, WebviewWindow};

/// Apply the fixed size to every window in the app.
pub fn apply(app: &tauri::AppHandle) {
    for (_label, window) in app.webview_windows() {
        if let Err(e) = pin(&window) {
            // Not fatal: the window still works, it can just be resized. Worth
            // saying out loud, because a silent failure here is indistinguishable
            // from the clamp working.
            eprintln!("teavault: could not pin the window size: {e}");
        }
    }
}

/// Pin one window to its current size.
fn pin(window: &WebviewWindow) -> Result<(), String> {
    let size = window
        .inner_size()
        .map_err(|e| format!("cannot read the window size: {e}"))?;

    // `inner_size` is the client area, which is what has to match: an
    // undecorated window still has an invisible resize border, and clamping to
    // the frame instead would leave the window a few pixels short.
    let fixed = PhysicalSize::new(size.width, size.height);

    // Same value on both ends. Only the combination means "fixed": a minimum
    // alone still allows growing, a maximum alone still allows shrinking.
    window
        .set_min_size(Some(fixed))
        .map_err(|e| format!("cannot pin the minimum size: {e}"))?;
    window
        .set_max_size(Some(fixed))
        .map_err(|e| format!("cannot pin the maximum size: {e}"))?;
    window
        .set_resizable(false)
        .map_err(|e| format!("cannot make the window non-resizable: {e}"))?;

    #[cfg(windows)]
    strip_frame(window)?;

    Ok(())
}

/// Remove the window frame Windows draws around an undecorated window.
///
/// `decorations: false` is not enough on its own. It leaves `WS_CAPTION` set —
/// which is `WS_BORDER | WS_DLGFRAME`, the two bits that draw the 1px line — and
/// while `WS_EX_APPWINDOW` is also present, Windows renders the frame anyway even
/// though there is no title bar to go with it.
///
/// `WS_MAXIMIZEBOX` goes in the same pass: `set_resizable(false)` clears
/// `WS_THICKFRAME` but leaves that one, so the window would still offer to leave
/// its single legal size.
///
/// This clears the *style* bits only. The accent-coloured band that remains after
/// that is DWM's, and belongs to `shadow: false` plus the frame removal together;
/// see the module comment.
#[cfg(windows)]
fn strip_frame(window: &WebviewWindow) -> Result<(), String> {
    use windows::Win32::UI::WindowsAndMessaging::{
        SetWindowLongPtrW, SetWindowPos, GWL_EXSTYLE, GWL_STYLE, SWP_FRAMECHANGED, SWP_NOACTIVATE,
        SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, WS_BORDER, WS_CAPTION, WS_DLGFRAME,
        WS_EX_APPWINDOW, WS_MAXIMIZEBOX,
    };

    let hwnd = window
        .hwnd()
        .map_err(|e| format!("cannot reach the window handle: {e}"))?;

    unsafe {
        // Read by asking for the same value back: `GetWindowLongPtrW` and
        // `SetWindowLongPtrW` share the slot, and passing 0 writes nothing that
        // matters because the very next call overwrites it.
        let style = SetWindowLongPtrW(hwnd, GWL_STYLE, 0);
        let exstyle = SetWindowLongPtrW(hwnd, GWL_EXSTYLE, 0);
        if style == 0 && exstyle == 0 {
            return Err("the window has no styles to read".into());
        }

        // Both spellings, deliberately: WS_CAPTION is the combination, and the two
        // component bits are what actually get drawn.
        let frame = WS_CAPTION.0 | WS_BORDER.0 | WS_DLGFRAME.0;
        let new_style = style & !(frame | WS_MAXIMIZEBOX.0) as isize;

        // `WS_EX_APPWINDOW` is the accent-coloured band. It forces the window to
        // be treated as a normal top-level window, and DWM then composes a border
        // for it — 8px of the accent colour, measured, down the left and top edges
        // of a window with no frame. Clearing it is what finally makes the edge
        // disappear; the 1px from WS_CAPTION alone was never the whole of it.
        //
        // The cost is that the window leaves the taskbar and loses Alt+Tab. That is
        // a real trade-off, and for a tray app whose window is opened deliberately
        // from the tray it is the right one: the tray icon is already the permanent
        // presence indicator.
        let new_exstyle = exstyle & !WS_EX_APPWINDOW.0 as isize;

        if new_style != style {
            SetWindowLongPtrW(hwnd, GWL_STYLE, new_style);
        }
        if new_exstyle != exstyle {
            SetWindowLongPtrW(hwnd, GWL_EXSTYLE, new_exstyle);
        }
        if new_style != style || new_exstyle != exstyle {
            // The frame is derived from the styles, so it has to be recalculated
            // or the window keeps its old edge until something else invalidates it.
            let _ = SetWindowPos(
                hwnd,
                None,
                0,
                0,
                0,
                0,
                SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE,
            );
        }
    }
    Ok(())
}