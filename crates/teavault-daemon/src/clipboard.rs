//! Windows clipboard.
//!
//! `unsafe`, confined to this file so the core stays `#![deny(unsafe_code)]`.
//!
//! The one rule implemented here is the one that matters: **clear only if the
//! content is still ours.** A password manager that eats an unrelated copied
//! password is worse than one that never clears at all.

#![allow(dead_code)]

use std::ptr;

use teavault_core::{clipboard::Clipboard, error::Error, error::Result};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{HANDLE, HGLOBAL},
        System::{
            DataExchange::{
                CloseClipboard, GetClipboardData, OpenClipboard, RegisterClipboardFormatW,
                SetClipboardData,
            },
            Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE},
        },
    },
};

/// `CF_UNICODETEXT` is 13, per the Win32 headers. The registered format is
/// preferred when it differs, so query it once per call rather than trusting the
/// constant blindly.
const CF_UNICODETEXT_FALLBACK: u32 = 13;

fn io(context: &'static str, e: windows::core::Error) -> Error {
    Error::io(context, std::io::Error::other(e.to_string()))
}

/// Open the clipboard, run `f`, and always close it.
///
/// The clipboard is a single global resource: leaving it open on any path would
/// block every other application on the desktop.
fn with_clipboard<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    unsafe {
        OpenClipboard(None).map_err(|e| io("open the clipboard", e))?;
        struct Guard;
        impl Drop for Guard {
            fn drop(&mut self) {
                unsafe {
                    let _ = CloseClipboard();
                }
            }
        }
        let _guard = Guard;
        f()
    }
}

fn unicode_format() -> u32 {
    let name: Vec<u16> = "CF_UNICODETEXT"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let id = unsafe { RegisterClipboardFormatW(PCWSTR(name.as_ptr())) };
    if id == 0 {
        CF_UNICODETEXT_FALLBACK
    } else {
        id
    }
}

fn read_text() -> Result<Option<String>> {
    with_clipboard(|| {
        let handle = unsafe { GetClipboardData(unicode_format()) }
            .map_err(|e| io("read the clipboard", e))?;
        if handle.is_invalid() {
            // Nothing of that format on the clipboard: not ours.
            return Ok(None);
        }
        unsafe {
            let p = GlobalLock(HGLOBAL(handle.0));
            if p.is_null() {
                return Ok(None);
            }
            let text = read_wide(p as *const u16);
            let _ = GlobalUnlock(HGLOBAL(handle.0));
            Ok(text)
        }
    })
}

unsafe fn read_wide(p: *const u16) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let mut len = 0usize;
    while *p.add(len) != 0 {
        len += 1;
    }
    Some(String::from_utf16_lossy(std::slice::from_raw_parts(p, len)))
}

fn write_text(text: &str) -> Result<()> {
    with_clipboard(|| {
        unsafe {
            // CF_UNICODETEXT requires a double NUL terminator.
            let mut wide: Vec<u16> = text.encode_utf16().collect();
            wide.push(0);
            wide.push(0);

            let bytes = std::mem::size_of_val(&wide[..]);
            let hg = GlobalAlloc(GMEM_MOVEABLE, bytes).map_err(|_| {
                Error::io(
                    "clipboard",
                    std::io::Error::other("could not allocate clipboard memory"),
                )
            })?;

            let p = GlobalLock(HGLOBAL(hg.0));
            if p.is_null() {
                let _ = windows::Win32::Foundation::GlobalFree(Some(HGLOBAL(hg.0)));
                return Err(Error::io(
                    "clipboard",
                    std::io::Error::other("could not lock clipboard memory"),
                ));
            }
            ptr::copy_nonoverlapping(wide.as_ptr(), p as *mut u16, wide.len());
            let _ = GlobalUnlock(HGLOBAL(hg.0));

            // Ownership transfers to the clipboard on success; on failure we
            // still own it and must free it.
            if SetClipboardData(unicode_format(), Some(HANDLE(hg.0))).is_err() {
                let _ = windows::Win32::Foundation::GlobalFree(Some(HGLOBAL(hg.0)));
                return Err(Error::io("clipboard", std::io::Error::last_os_error()));
            }
            Ok(())
        }
    })
}

fn clear() -> Result<()> {
    with_clipboard(|| {
        unsafe {
            // Emptying rather than removing the format, so the clipboard still
            // exists for whatever the user copies next.
            SetClipboardData(unicode_format(), None)
                .map_err(|_| Error::io("clipboard", std::io::Error::last_os_error()))?;
            Ok(())
        }
    })
}

/// The real clipboard.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsClipboard;

impl Clipboard for WindowsClipboard {
    fn set(&self, text: &str) -> Result<()> {
        write_text(text)
    }

    fn get(&self) -> Result<Option<String>> {
        read_text()
    }

    fn clear_if_unchanged(&self, expected: &str) -> Result<bool> {
        match read_text()? {
            Some(current) if current == expected => {
                clear()?;
                Ok(true)
            }
            // Something else is there, or nothing is. Either way, not ours.
            _ => Ok(false),
        }
    }
}
