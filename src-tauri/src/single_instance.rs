//! One instance of a process, enforced by a named mutex.
//!
//! The UI and the daemon both need this, for different reasons, and both already
//! had a hand-rolled version of it. Extracted so there is one implementation and
//! one set of arguments to get right.
//!
//! ## What it does and does not prevent
//!
//! It prevents a second *process*. It does not prevent a second *window*: the
//! window is created by the single process that holds the mutex, so there is only
//! ever one.
//!
//! It is a named mutex rather than a file lock or a port because Windows already
//! solves this, releases the handle when the process dies — including on a crash,
//! where a file lock would leave a stale file — and makes the owner explicit.

use std::ffi::c_void;

/// Holds the mutex for as long as this value lives.
///
/// Dropping it closes the handle, which releases the mutex. Nothing else in the
/// program has to remember to do that.
pub struct Instance(*mut c_void);

/// Take the named mutex, or report that somebody else already has it.
///
/// `name` is a bare suffix; the `Local\` namespace is added here so the scope is
/// always the current session. A global namespace would let one user's TEAvault
/// block another's, which is not a failure mode this product should have.
pub fn acquire(name: &str) -> Result<Instance, String> {
    use windows::Win32::{
        Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS},
        System::Threading::CreateMutexW,
    };

    let full = format!("Local\\{name}");
    let wide: Vec<u16> = full.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let handle = CreateMutexW(None, true, windows::core::PCWSTR(wide.as_ptr()))
            .map_err(|e| format!("could not create the instance mutex: {e}"))?;

        // `GetLastError` must be read immediately; any other call resets it.
        if GetLastError() == ERROR_ALREADY_EXISTS {
            let _ = CloseHandle(handle);
            return Err("another TEAvault window is already open — use the tray icon instead".into());
        }
        Ok(Instance(handle.0))
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(
                windows::Win32::Foundation::HANDLE(self.0),
            );
        }
    }
}
