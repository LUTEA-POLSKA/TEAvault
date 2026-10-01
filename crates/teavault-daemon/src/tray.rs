//! The system tray icon and its menu.
//!
//! `Shell_NotifyIcon` directly rather than a tray crate: it is one icon, one
//! menu and one message loop, and a dependency here would be one more thing to
//! audit in a program whose job is to hold secrets.
//!
//! ## Idle cost
//!
//! The tray is the daemon's main message pump, so it costs one blocked
//! `GetMessage` and nothing else. No animation, no timer, no periodic redraw.
//!
//! ## Menu
//!
//! Open · Lock now · Recent requests · Settings · Quit. Anything that needs the
//! window spawns the UI process, which keeps the WebView absent until the user
//! asks for it.

#![allow(dead_code)]

use windows::{
    core::w,
    Win32::{
        Foundation::{
            GetLastError, ERROR_CLASS_ALREADY_EXISTS, HWND, LPARAM, LRESULT, POINT, WPARAM,
        },
        System::LibraryLoader::GetModuleHandleW,
        UI::{
            Shell::{
                Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY,
                NOTIFYICONDATAW,
            },
            WindowsAndMessaging::{
                AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu,
                DestroyWindow, DispatchMessageW, GetCursorPos, GetMessageW, LoadIconW,
                PostQuitMessage, RegisterClassW, SetForegroundWindow, TrackPopupMenu,
                TranslateMessage, IDI_APPLICATION, MF_STRING, MSG, TPM_BOTTOMALIGN,
                TPM_RIGHTBUTTON, WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_COMMAND, WM_DESTROY,
                WM_LBUTTONDBLCLK, WM_RBUTTONUP, WNDCLASSW,
            },
        },
    },
};

/// A private window message, so command ids cannot collide with the shell's.
const WM_TRAY: u32 = WM_APP + 1;

/// What the user chose from the tray.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    Open,
    LockNow,
    Recent,
    Settings,
    Quit,
}

impl TrayAction {
    const fn command_id(self) -> usize {
        match self {
            Self::Open => 1001,
            Self::LockNow => 1002,
            Self::Recent => 1003,
            Self::Settings => 1004,
            Self::Quit => 1005,
        }
    }

    fn from_command(id: usize) -> Option<Self> {
        match id {
            1001 => Some(Self::Open),
            1002 => Some(Self::LockNow),
            1003 => Some(Self::Recent),
            1004 => Some(Self::Settings),
            1005 => Some(Self::Quit),
            _ => None,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Open => "Open TEAvault",
            Self::LockNow => "Lock now",
            Self::Recent => "Recent requests",
            Self::Settings => "Settings",
            Self::Quit => "Quit TEAvault",
        }
    }

    const ALL: [TrayAction; 5] = [
        TrayAction::Open,
        TrayAction::LockNow,
        TrayAction::Recent,
        TrayAction::Settings,
        TrayAction::Quit,
    ];
}

/// A hidden message-only window that owns the icon.
pub struct Tray {
    hwnd: HWND,
    added: bool,
}

/// What the pump decided.
#[derive(Debug, PartialEq, Eq)]
pub enum Pump {
    Quit,
}

impl Tray {
    /// Create the window and add the icon.
    pub fn new(tip: &str) -> Result<Self, String> {
        unsafe {
            let instance = GetModuleHandleW(None).map_err(|e| e.to_string())?;
            let class_name = w!("TEAvaultTrayWindow");

            let wc = WNDCLASSW {
                lpfnWndProc: Some(def_window_proc),
                hInstance: instance.into(),
                lpszClassName: class_name,
                ..Default::default()
            };
            // A second daemon in the same session fails here, which is a useful
            // backstop to the named mutex.
            if RegisterClassW(&wc) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS {
                return Err("registering the tray window class failed".into());
            }

            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                class_name,
                w!("TEAvault"),
                WINDOW_STYLE(0),
                0,
                0,
                0,
                0,
                None,
                None,
                Some(instance.into()),
                None,
            )
            .map_err(|e| format!("creating the tray window failed: {e}"))?;

            let mut tray = Self { hwnd, added: false };
            tray.add_icon(tip)?;
            Ok(tray)
        }
    }

    fn add_icon(&mut self, tip: &str) -> Result<(), String> {
        unsafe {
            let mut data = NOTIFYICONDATAW {
                cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                hWnd: self.hwnd,
                uID: 1,
                uFlags: NIF_MESSAGE | NIF_TIP | NIF_ICON,
                uCallbackMessage: WM_TRAY,
                ..Default::default()
            };
            copy_wide(tip, &mut data.szTip);
            // The shell's default application icon. Shipping an .ico would mean
            // embedding a binary asset, which is not worth the review surface.
            data.hIcon = LoadIconW(None, IDI_APPLICATION).unwrap_or_default();

            if Shell_NotifyIconW(NIM_ADD, &data).as_bool() {
                self.added = true;
                Ok(())
            } else {
                Err("Shell_NotifyIconW(NIM_ADD) failed".into())
            }
        }
    }

    /// Update the tooltip, e.g. to show locked state.
    pub fn set_tip(&self, tip: &str) {
        if !self.added {
            return;
        }
        unsafe {
            let mut data = NOTIFYICONDATAW {
                cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                hWnd: self.hwnd,
                uID: 1,
                uFlags: NIF_TIP,
                ..Default::default()
            };
            copy_wide(tip, &mut data.szTip);
            let _ = Shell_NotifyIconW(NIM_MODIFY, &data);
        }
    }

    /// Show the context menu at the cursor and report what was chosen.
    pub fn show_menu(&self) -> Option<TrayAction> {
        unsafe {
            let menu = CreatePopupMenu().ok()?;
            for action in TrayAction::ALL {
                // `AppendMenuW` copies the label, so the buffer only has to live
                // for the call.
                let label: Vec<u16> = action
                    .label()
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();
                let _ = AppendMenuW(
                    menu,
                    MF_STRING,
                    action.command_id(),
                    windows::core::PCWSTR(label.as_ptr()),
                );
            }

            let mut pt = POINT::default();
            let _ = GetCursorPos(&mut pt);
            // Required so the menu dismisses when the user clicks elsewhere.
            let _ = SetForegroundWindow(self.hwnd);

            let cmd = TrackPopupMenu(
                menu,
                TPM_RIGHTBUTTON | TPM_BOTTOMALIGN,
                pt.x,
                pt.y,
                None,
                self.hwnd,
                None,
            );
            let _ = DestroyMenu(menu);
            if cmd.0 as usize == 0 {
                None
            } else {
                TrayAction::from_command(cmd.0 as usize)
            }
        }
    }

    /// Pump messages until the user quits or `on_action` asks to stop.
    pub fn pump(&self, mut on_action: impl FnMut(TrayAction)) -> Result<Pump, String> {
        unsafe {
            let mut msg: MSG = std::mem::zeroed();
            loop {
                let r = GetMessageW(&mut msg, None, 0, 0);
                if r.0 <= 0 {
                    return Ok(Pump::Quit);
                }
                match msg.message {
                    WM_TRAY => match msg.lParam.0 as u32 {
                        WM_RBUTTONUP => {
                            if let Some(action) = self.show_menu() {
                                on_action(action);
                            }
                        }
                        WM_LBUTTONDBLCLK => on_action(TrayAction::Open),
                        _ => {}
                    },
                    WM_COMMAND => {
                        if let Some(action) = TrayAction::from_command(msg.wParam.0 as usize) {
                            on_action(action);
                        }
                    }
                    WM_DESTROY => return Ok(Pump::Quit),
                    _ => {
                        let _ = TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                }
            }
        }
    }

    /// Ask the pump to stop.
    pub fn request_quit(&self) {
        unsafe {
            PostQuitMessage(0);
        }
    }
}

impl Drop for Tray {
    fn drop(&mut self) {
        unsafe {
            let data = NOTIFYICONDATAW {
                cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                hWnd: self.hwnd,
                uID: 1,
                ..Default::default()
            };
            // Without this the icon lingers until the user hovers it.
            let _ = Shell_NotifyIconW(NIM_DELETE, &data);
            let _ = DestroyWindow(self.hwnd);
        }
    }
}

unsafe extern "system" fn def_window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

/// Copy into a fixed-size wide buffer, always NUL-terminating.
fn copy_wide(src: &str, dst: &mut [u16]) {
    let mut i = 0usize;
    for c in src.encode_utf16() {
        if i + 1 >= dst.len() {
            break;
        }
        dst[i] = c;
        i += 1;
    }
    dst[i] = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_ids_round_trip() {
        for a in TrayAction::ALL {
            assert_eq!(TrayAction::from_command(a.command_id()), Some(a));
        }
    }

    #[test]
    fn an_unknown_command_is_ignored() {
        assert_eq!(TrayAction::from_command(9999), None);
        assert_eq!(TrayAction::from_command(0), None);
    }

    #[test]
    fn every_action_has_a_distinct_id_and_label() {
        let mut ids: Vec<usize> = TrayAction::ALL.iter().map(|a| a.command_id()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), TrayAction::ALL.len());

        let mut labels: Vec<&str> = TrayAction::ALL.iter().map(|a| a.label()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), TrayAction::ALL.len());
    }

    #[test]
    fn wide_copy_terminates_and_truncates_without_overflowing() {
        let mut buf = [0u16; 8];
        copy_wide("abc", &mut buf);
        assert_eq!(&buf[..4], &[b'a' as u16, b'b' as u16, b'c' as u16, 0]);

        let mut small = [0u16; 4];
        copy_wide("a much longer string", &mut small);
        assert_eq!(small[3], 0, "the buffer must stay terminated");

        // A single slot can hold only the terminator.
        let mut one = [0xAAAAu16; 1];
        copy_wide("x", &mut one);
        assert_eq!(one[0], 0);
    }
}
