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
                AppendMenuW, CreateIconFromResourceEx, CreatePopupMenu, CreateWindowExW,
                DefWindowProcW, DestroyIcon, DestroyMenu, DestroyWindow, DispatchMessageW,
                GetCursorPos, GetMessageW, GetSystemMetrics, PostQuitMessage, RegisterClassW,
                SetForegroundWindow, TrackPopupMenu, TranslateMessage, HICON, IMAGE_FLAGS,
                MF_STRING, MSG, SM_CXSMICON, TPM_BOTTOMALIGN, TPM_RIGHTBUTTON, WINDOW_EX_STYLE,
                WINDOW_STYLE, WM_APP, WM_COMMAND, WM_DESTROY, WM_LBUTTONDBLCLK, WM_RBUTTONUP,
                WNDCLASSW,
            },
        },
    },
};

/// The application's icon, embedded at build time so the tray needs no files on
/// disk. See `load_icon` for why it is parsed rather than loaded by path.
const ICON_BYTES: &[u8] = include_bytes!("../../../src-tauri/icons/icon.ico");

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
    /// The icon handed to the shell. Owned, because it came from
    /// `CreateIconFromResourceEx` rather than from `LoadIconW`: a loaded icon is
    /// shared and must not be destroyed, a created one leaks if it is not.
    icon: HICON,
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

            let mut tray = Self {
                hwnd,
                added: false,
                icon: load_icon()?,
            };
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
            data.hIcon = self.icon;

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
            // After the shell is told the icon is gone. Destroying first would
            // leave a handle the shell could still be reading.
            let _ = DestroyIcon(self.icon);
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

/// The application's icon, at whatever size the current display wants.
///
/// ## Why not `LoadIconW(None, IDI_APPLICATION)`
///
/// That is the shell's generic "some program" icon. Every vault manager would then
/// be indistinguishable in the tray, which is the one place the user has to
/// recognise the app at a glance.
///
/// ## Why the .ico is parsed here
///
/// `LoadImageW` takes a *file path*, which would mean locating an asset on disk at
/// runtime and guessing where the installer put it. Embedding the bytes with
/// `include_bytes!` keeps the icon inside the binary, so there is nothing to find,
/// nothing to go missing, and no path to get wrong. A compiled-in blob is also
/// reviewable: the same file is committed next to the source that documents it.
///
/// The path reaches across into `src-tauri/` because Tauri requires its icons
/// there. One source of truth is worth more here than a tidy module boundary, and
/// a wrong path fails the build rather than the tray.
///
/// ## Why the size is chosen per display
///
/// The tray icon is not a fixed pixel size: `SM_CXSMICON` is 16 at 100% and 24 at
/// 150%. Handing the shell a 32px icon to downscale makes Windows resample it, and
/// a resampled icon is visibly soft. So the metric is asked for and the smallest
/// frame that covers it is used.
fn load_icon() -> Result<HICON, String> {
    let frames = parse_ico(ICON_BYTES)?;

    let wanted = unsafe { GetSystemMetrics(SM_CXSMICON) }.max(16) as usize;
    let chosen = pick_frame(&frames, wanted).ok_or("embedded icon has no usable frame")?;

    unsafe {
        // The frame bytes are a bare icon, not a whole .ico file: that is what a
        // directory entry points at. `dwver` 0x00030000 is icon version 3, which is
        // what lets Windows read the PNG-compressed frames the bundler writes.
        //
        // cxdesired/cydesired of zero with empty flags means "use the size it
        // already is". Passing the metric here would make Win32 resample a frame
        // that was selected to match it in the first place.
        CreateIconFromResourceEx(
            &ICON_BYTES[chosen.offset..chosen.offset + chosen.len],
            true,
            0x0003_0000,
            0,
            0,
            IMAGE_FLAGS(0),
        )
        .map_err(|e| format!("CreateIconFromResourceEx failed: {e}"))
    }
}

/// One frame in the .ico directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IconFrame {
    /// Pixel size of the square frame.
    size: usize,
    /// Where the frame's bytes start in the file.
    offset: usize,
    /// How many bytes the frame occupies.
    len: usize,
}

/// Read the directory of an .ico file.
///
/// Six byte header, then one sixteen byte entry per frame. Widths are a single
/// byte, so 256 is stored as zero and has to be restored by hand.
///
/// Entries whose offset or length runs past the end of the blob are dropped rather
/// than reported: a truncated icon should still yield its usable frames, and a
/// frame that would hand `CreateIconFromResourceEx` a slice out of bounds is worse
/// than no frame at all.
fn parse_ico(ico: &[u8]) -> Result<Vec<IconFrame>, String> {
    const HEADER: usize = 6;
    const ENTRY: usize = 16;

    if ico.len() < HEADER {
        return Err("embedded icon is truncated".into());
    }
    if u16::from_le_bytes([ico[2], ico[3]]) != 1 {
        return Err("embedded icon is not an .ico".into());
    }

    let count = u16::from_le_bytes([ico[4], ico[5]]) as usize;
    let frames: Vec<IconFrame> = (0..count)
        .filter_map(|i| {
            let o = HEADER + i * ENTRY;
            let raw = *ico.get(o)?;
            let size = if raw == 0 { 256 } else { raw as usize };
            let len =
                u32::from_le_bytes([ico[o + 8], ico[o + 9], ico[o + 10], ico[o + 11]]) as usize;
            let offset =
                u32::from_le_bytes([ico[o + 12], ico[o + 13], ico[o + 14], ico[o + 15]]) as usize;
            let end = offset.checked_add(len)?;
            if end > ico.len() {
                return None;
            }
            Some(IconFrame { size, offset, len })
        })
        .collect();

    if frames.is_empty() {
        return Err("embedded icon has no usable frame".into());
    }
    Ok(frames)
}

/// The frame to hand the shell: the smallest one that covers `wanted`, so the icon
/// is never upscaled, and never downscaled either when an exact match exists.
/// Falls back to the largest frame, because a scaled-up icon beats no icon.
fn pick_frame(frames: &[IconFrame], wanted: usize) -> Option<&IconFrame> {
    frames
        .iter()
        .filter(|f| f.size >= wanted)
        .min_by_key(|f| f.size)
        .or_else(|| frames.iter().max_by_key(|f| f.size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::UI::WindowsAndMessaging::{GetIconInfo, ICONINFO};

    #[test]
    fn the_embedded_icon_parses_and_offers_the_tray_sizes() {
        // This is the test that would have caught a corrupt or truncated icon,
        // which otherwise shows up as an invisible tray entry at runtime.
        let frames = parse_ico(ICON_BYTES).expect("embedded icon parses");
        let sizes: Vec<usize> = frames.iter().map(|f| f.size).collect();

        // Windows asks for 16 at 100% and 24 at 150%. Both must be present as
        // exact frames, or the shell resamples a neighbour and the icon goes soft.
        for want in [16, 24, 32] {
            assert!(
                sizes.contains(&want),
                "no exact {want}px frame, only {sizes:?}"
            );
        }
        assert!(sizes.contains(&256), "no 256px frame for the installer");

        // The 256px frame is stored with a zero width byte; make sure that was
        // decoded back to 256 rather than left as 0.
        assert!(!sizes.contains(&0), "a 256px frame decoded as 0: {sizes:?}");
    }

    #[test]
    fn every_frame_points_inside_the_file() {
        for f in parse_ico(ICON_BYTES).expect("embedded icon parses") {
            assert!(
                f.offset + f.len <= ICON_BYTES.len(),
                "frame {f:?} runs past the end of the blob"
            );
            assert!(f.len > 0, "frame {f:?} is empty");
        }
    }

    #[test]
    fn frame_selection_never_upscales_when_an_exact_one_exists() {
        let frames = [
            IconFrame {
                size: 16,
                offset: 0,
                len: 10,
            },
            IconFrame {
                size: 24,
                offset: 10,
                len: 10,
            },
            IconFrame {
                size: 32,
                offset: 20,
                len: 10,
            },
        ];
        assert_eq!(pick_frame(&frames, 16).map(|f| f.size), Some(16));
        assert_eq!(pick_frame(&frames, 17).map(|f| f.size), Some(24));
        assert_eq!(pick_frame(&frames, 24).map(|f| f.size), Some(24));
        // 30 is not available, so the next size up is used rather than a downscale.
        assert_eq!(pick_frame(&frames, 30).map(|f| f.size), Some(32));
        // Past the largest frame, the largest is better than nothing.
        assert_eq!(pick_frame(&frames, 512).map(|f| f.size), Some(32));
    }

    #[test]
    fn a_malformed_icon_is_rejected_rather_than_trusted() {
        assert!(parse_ico(&[]).is_err(), "empty blob");
        assert!(parse_ico(&[0, 0, 0, 0, 0, 0]).is_err(), "truncated header");
        // Type 2 is a cursor, not an icon.
        assert!(parse_ico(&[0, 0, 2, 0, 0, 0]).is_err(), "not an icon");
        // A valid header claiming a frame that runs past the end.
        let mut lying = vec![0u8; 6];
        lying[2] = 1;
        lying[4] = 1;
        lying.extend_from_slice(&[16, 16, 0, 0, 1, 0, 32, 0]);
        lying.extend_from_slice(&u32::MAX.to_le_bytes());
        lying.extend_from_slice(&0u32.to_le_bytes());
        assert!(parse_ico(&lying).is_err(), "frame past the end of the blob");
    }

    #[test]
    fn win32_accepts_the_embedded_icon() {
        // The tests above only prove the directory is well formed. This one goes
        // through the whole path: real bytes, real `CreateIconFromResourceEx`, real
        // `GetIconInfo`. If a future edit corrupts the .ico, or the frames stop
        // being PNG-compressed, this fails here rather than as an invisible tray
        // entry that nobody notices until they go looking for the app.
        if cfg!(not(windows)) {
            return;
        }

        let icon = load_icon().expect("Win32 builds an icon from the embedded bytes");
        unsafe {
            let mut info = ICONINFO::default();
            GetIconInfo(icon, &mut info).expect("GetIconInfo accepts the icon");
            assert!(!info.hbmColor.is_invalid(), "the icon has no colour bitmap");
            let _ = DestroyIcon(icon);
        }
    }

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
