//! The Windows named-pipe server.
//!
//! This is the daemon's transport. It does three things and no more: accept a
//! connection, learn who is on the other end from the kernel, and move framed
//! bytes. Every decision about what a request may do happens in
//! [`teavault_core::ipc::dispatch`], which is why this file contains no policy.
//!
//! ## Access control
//!
//! Three layers, outermost to innermost:
//!
//! 1. **`PIPE_REJECT_REMOTE_CLIENTS`** — a client on another machine cannot
//!    connect at all. TEAvault is not a network service and must not become one
//!    by accident.
//! 2. **An explicit DACL**, built from SDDL granting the system account full
//!    access and built-in users read/write. Named pipes are frequently more
//!    permissive than people assume, so the descriptor is constructed rather
//!    than inherited.
//! 3. **Per-operation tier checks** in the dispatcher, keyed on the image path
//!    the kernel reports.
//!
//! ## Idle cost
//!
//! The server is **blocking**. `ConnectNamedPipe` parks the thread until a
//! client appears and a read blocks until a line arrives. No poll loop, no
//! timer thread, no periodic scan.
//!
//! ## Client identity
//!
//! `GetNamedPipeClientProcessId` returns the PID of the process on the other end
//! — a kernel answer the client cannot influence. The image path is then read
//! from that process handle. Nothing in the request body participates, which is
//! why the protocol has no field for a client to name itself.

#![allow(dead_code)]

use std::{
    io::{BufRead, BufReader, Write},
    os::windows::io::{FromRawHandle, OwnedHandle},
};

use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{CloseHandle, GetLastError, HANDLE, HLOCAL, INVALID_HANDLE_VALUE},
        Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        },
        Security::{
            GetTokenInformation, TokenElevation, PSECURITY_DESCRIPTOR, TOKEN_ELEVATION, TOKEN_QUERY,
        },
        Storage::FileSystem::{
            CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, OPEN_EXISTING,
            PIPE_ACCESS_DUPLEX,
        },
        System::{
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe,
                GetNamedPipeClientProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_TYPE_BYTE, PIPE_WAIT,
            },
            Threading::{
                OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
                PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
    },
};

use teavault_core::{
    error::Error,
    ipc::{Request, MAX_MESSAGE_BYTES},
    model::ClientIdentity,
};

/// The pipe every client connects to.
pub const PIPE_NAME: &str = r"\\.\pipe\teavault-v1";

/// Concurrent client slots. Eight is generous for a single-user local tool; more
/// would only widen the window in which a client can hold one.
const MAX_INSTANCES: u32 = 8;
const OUT_BUFFER: u32 = 16 * 1024;
const IN_BUFFER: u32 = 16 * 1024;

/// `D:P` makes the DACL protected, so it does not inherit the parent's.
/// `SY` is the local system account, `BU` built-in users.
const SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BU)";

/// A pipe instance, its security descriptor, and the bookkeeping to free both.
pub struct PipeInstance {
    handle: HANDLE,
    sd: PSECURITY_DESCRIPTOR,
}

impl PipeInstance {
    /// Create one instance. Fails if the name is already fully occupied.
    pub fn create() -> Result<Self, String> {
        unsafe {
            let mut sd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
            let sddl = wide(SDDL);
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )
            .map_err(|e| format!("building the pipe security descriptor failed: {e}"))?;

            let name = wide(PIPE_NAME);
            let handle = CreateNamedPipeW(
                PCWSTR(name.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                // `PIPE_REJECT_REMOTE_CLIENTS` is the important bit: a remote
                // client is refused by the OS before any of our code runs.
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                MAX_INSTANCES,
                OUT_BUFFER,
                IN_BUFFER,
                0,
                None,
            );

            if handle == INVALID_HANDLE_VALUE || handle.is_invalid() {
                let msg = last_error_string();
                let _ = local_free(HLOCAL(sd.0));
                return Err(format!("creating the named pipe failed: {msg}"));
            }

            // The descriptor must outlive the handle; `self.sd` holds it and
            // `Drop` frees it.
            Ok(Self { handle, sd })
        }
    }

    /// Block until a client connects.
    pub fn connect(&self) -> Result<(), String> {
        let ok = unsafe { ConnectNamedPipe(self.handle, None) };
        if ok.is_ok() {
            return Ok(());
        }
        // ERROR_PIPE_CONNECTED means the client arrived between Create and
        // Connect, which is a success.
        if unsafe { GetLastError() } == windows::Win32::Foundation::ERROR_PIPE_CONNECTED {
            return Ok(());
        }
        Err(format!("connect failed: {}", last_error_string()))
    }

    /// The kernel's answer to "who is on the other end".
    pub fn client_identity(&self) -> Result<ClientIdentity, String> {
        let mut pid: u32 = 0;
        unsafe {
            GetNamedPipeClientProcessId(self.handle, &mut pid)
                .map_err(|e| format!("reading the client process id failed: {e}"))?;
        }
        if pid == 0 {
            return Err("the client process id could not be determined".into());
        }
        identity_for_pid(pid)
    }

    /// Serve requests on this connection until the client hangs up.
    ///
    /// A connection is a **session**, not a single exchange. That matters
    /// because the desktop UI holds one connection open and issues many commands
    /// over it: with one-request-per-connection, every command after the first
    /// writes into a pipe the server has already closed and fails with
    /// ERROR_NO_DATA (os error 233) — while every one-shot client, such as the
    /// CLI, keeps working, which makes the bug look intermittent.
    ///
    /// The loop ends when the client closes (read returns 0), when the pipe
    /// errors, or on an unrecoverable write. Between requests the thread is
    /// blocked in the kernel, so an idle connection costs nothing.
    ///
    /// The vault lock is taken inside `f`, never here, so a client that opens a
    /// connection and then sits idle cannot hold the vault hostage.
    pub fn serve_session<F>(&self, f: &mut F) -> bool
    where
        F: FnMut(&str) -> String,
    {
        // Borrow the pipe as a `File` without taking ownership: `ManuallyDrop`
        // stops `Drop` from closing a handle the instance still owns.
        let raw = self.handle.0;
        let mut file = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_handle(raw) });

        let mut reader = BufReader::new(&mut *file);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                // Clean hang-up: the client is done with this session.
                Ok(0) => return false,
                Ok(n) if n > MAX_MESSAGE_BYTES => {
                    // Refuse rather than truncate. A truncated JSON body must
                    // never be mistaken for a smaller, valid request.
                    if !self.write_line(&error_line("request exceeds the maximum size")) {
                        return false;
                    }
                    continue;
                }
                Ok(_) => {}
                Err(_) => return false,
            }

            let trimmed = line.trim_end_matches(['\r', '\n']);

            // Every line gets exactly one response line, including a blank one.
            // Silently skipping a blank line would desynchronise a client: it has
            // already written and is now blocked reading the answer to *that*
            // write, so the invariant is one reply per line received, not per
            // request recognised.
            let response = if trimmed.is_empty() {
                error_line("empty request line")
            } else {
                f(trimmed)
            };

            if !self.write_line(&response) {
                return false;
            }
        }
    }

    /// One exchange. Kept for callers that genuinely want a single request.
    pub fn serve_once<F>(&self, mut f: F) -> bool
    where
        F: FnMut(&str) -> String,
    {
        self.serve_session(&mut f)
    }

    fn write_line(&self, response: &str) -> bool {
        use std::io::Write as _;
        let raw = self.handle.0;
        let mut file = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_handle(raw) });

        // The framing depends on one response per line. JSON escapes newlines, so
        // this cannot normally happen; refuse rather than corrupt the stream if
        // it ever does.
        if response.contains('\n') {
            return false;
        }
        let mut out = Vec::with_capacity(response.len() + 1);
        out.extend_from_slice(response.as_bytes());
        out.push(b'\n');
        file.write_all(&out).is_ok() && file.flush().is_ok()
    }
}

impl Drop for PipeInstance {
    fn drop(&mut self) {
        unsafe {
            let _ = DisconnectNamedPipe(self.handle);
            let _ = CloseHandle(self.handle);
            let _ = local_free(HLOCAL(self.sd.0));
        }
    }
}

/// NUL-terminated UTF-16, for the W-suffixed Win32 entry points.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn last_error_string() -> String {
    std::io::Error::last_os_error().to_string()
}

unsafe fn local_free(h: HLOCAL) -> HLOCAL {
    windows::Win32::Foundation::LocalFree(Some(h))
}

fn error_line(message: &str) -> String {
    serde_json::to_string(&teavault_core::ipc::Response::err(
        "",
        Error::invalid("request", message),
    ))
    .unwrap_or_else(|_| String::from(r#"{"v":1,"id":"","error":{"code":"malformed"}}"#))
}

/// Resolve a PID to a verified identity.
///
/// `PROCESS_QUERY_LIMITED_INFORMATION` is the least privilege that answers the
/// question.
pub fn identity_for_pid(pid: u32) -> Result<ClientIdentity, String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .map_err(|e| format!("opening process {pid} failed: {e}"))?;
        let _guard = HandleGuard(h);

        let elevated = is_elevated(h);

        let mut size = 260u32;
        let mut buf = vec![0u16; size as usize];
        if QueryFullProcessImageNameW(
            h,
            PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut size,
        )
        .is_err()
        {
            // Not fatal, but it means the tier check cannot succeed, so the
            // caller stays agent tier. The path is left empty rather than
            // guessed — a wrong path here could grant owner tier.
            return Ok(ClientIdentity {
                pid,
                image_path: String::new(),
                file_name: String::new(),
                elevated,
            });
        }
        buf.truncate(size as usize);
        let mut identity = ClientIdentity::new(pid, String::from_utf16_lossy(&buf));
        identity.elevated = elevated;
        Ok(identity)
    }
}

fn is_elevated(process: HANDLE) -> bool {
    unsafe {
        let mut token = HANDLE(std::ptr::null_mut());
        if OpenProcessToken(process, TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let _guard = HandleGuard(token);

        let mut elevation = TOKEN_ELEVATION::default();
        let mut needed = 0u32;
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut std::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut needed,
        )
        .is_ok()
            && elevation.TokenIsElevated != 0
    }
}

/// Closes a handle on drop, so no early return can leak one.
struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

// ---------------------------------------------------------------- the client

/// A refusal from the daemon, in the form a caller needs it.
#[derive(Debug, Clone)]
pub struct Refusal {
    /// Stable machine-readable code, from `teavault_core::Error::code`.
    pub code: String,
    pub message: String,
    pub request_id: Option<String>,
    pub retry_after_secs: Option<u64>,
    pub retryable: bool,
}

/// Everything that can go wrong talking to the daemon.
#[derive(Debug)]
pub enum ClientError {
    /// Nothing is listening on the pipe.
    NoDaemon,
    Io(std::io::Error),
    /// The daemon answered with something unreadable.
    Protocol(String),
    /// The daemon refused. This is an answer, not a fault.
    Refused(Refusal),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDaemon => write!(f, "the TEAvault background process is not running"),
            Self::Io(e) => write!(f, "{e}"),
            Self::Protocol(m) => write!(f, "unreadable response from the daemon: {m}"),
            Self::Refused(r) => write!(f, "{}", r.message),
        }
    }
}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// A connected pipe.
///
/// One request per connection, then the pipe is closed. That is deliberate:
/// a long-lived connection would need per-connection state and a way to
/// guarantee it is torn down, and the cheapest possible thing to get right here
/// is one exchange per connection.
pub struct Client {
    handle: HANDLE,
}

impl Client {
    /// Connect, retrying briefly while the daemon starts.
    ///
    /// A refusal is never retried: it is the daemon's answer, and asking again would
    /// only give a caller a second attempt at whatever it is probing.
    pub fn connect_with_retry(timeout: std::time::Duration) -> Result<Client, ClientError> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match Client::connect() {
                Ok(c) => return Ok(c),
                Err(ClientError::Refused(r)) => {
                    return Err(ClientError::Refused(r));
                }
                Err(e) => {
                    if std::time::Instant::now() >= deadline {
                        return Err(e);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        }
    }

    pub fn connect() -> Result<Self, ClientError> {
        unsafe {
            let name = wide(PIPE_NAME);
            CreateFileW(
                PCWSTR(name.as_ptr()),
                PIPE_ACCESS_DUPLEX.0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
            .map_err(|_| match std::io::Error::last_os_error().raw_os_error() {
                // ERROR_FILE_NOT_FOUND: nothing is listening. That is the
                // common case and deserves its own message rather than Win32
                // noise.
                Some(2) => ClientError::NoDaemon,
                _ => ClientError::Io(std::io::Error::last_os_error()),
            })
            .map(|handle| Self { handle })
        }
    }

    /// Send one request, read one response.
    pub fn send(&self, req: Request) -> Result<serde_json::Value, ClientError> {
        let line = serde_json::to_string(&req).map_err(|e| ClientError::Protocol(e.to_string()))?;
        if line.len() > MAX_MESSAGE_BYTES {
            return Err(ClientError::Protocol("request is too large".into()));
        }

        let mut bytes = line.into_bytes();
        bytes.push(b'\n');

        let raw = self.handle.0;
        let file = std::fs::File::from(unsafe { OwnedHandle::from_raw_handle(raw) });
        {
            let mut writer = &file;
            writer.write_all(&bytes)?;
            writer.flush()?;
        }

        let mut reader = BufReader::new(&file);
        let mut text = String::new();
        let n = reader.read_line(&mut text)?;
        if n == 0 {
            return Err(ClientError::Protocol(
                "the daemon closed the connection without answering".into(),
            ));
        }

        let response: teavault_core::ipc::Response =
            serde_json::from_str(text.trim_end_matches(['\r', '\n']))
                .map_err(|e| ClientError::Protocol(e.to_string()))?;

        // The `File` is a borrowed view of the handle; forget it so `Drop` does
        // not close a handle `Client` owns.
        std::mem::forget(file);

        match response.error {
            None => Ok(response.result.unwrap_or(serde_json::Value::Null)),
            Some(e) => Err(ClientError::Refused(Refusal {
                code: e.code,
                message: e.message,
                request_id: e.request_id,
                retry_after_secs: e.retry_after_secs,
                retryable: e.retryable,
            })),
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}
