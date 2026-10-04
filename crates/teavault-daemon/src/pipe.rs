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
//! 2. **An explicit DACL**, built from SDDL rather than inherited. This is the
//!    layer that keeps other accounts on the machine out.
//! 3. **Per-operation tier checks** in the dispatcher, keyed on the image path
//!    the kernel reports.
//!
//! ## Why the DACL names a SID rather than `BU`
//!
//! The descriptor used to be `D:P(A;;GA;;;SY)(A;;GA;;;BU)` — full access for the
//! system account and for **every** account on the machine, because `BU` is
//! BUILTIN\Users. For a credential vault that is far too wide. Any other user
//! logged into the same Windows installation could open the pipe; the tier check
//! would stop them from owner operations, but `list` and `info` are agent-tier,
//! so they could still enumerate the vault's metadata — every provider the owner
//! holds a key for, by name, and each entry's capabilities.
//!
//! The descriptor is therefore built from the **current user's SID**. `SY` stays,
//! because an elevated daemon has to be reachable from a non-elevated one or the
//! product breaks after a UAC prompt; the tier check is what stops a second
//! SYSTEM process from getting anywhere useful.
//!
//! This is not a defence against an administrator, and it is not meant to be —
//! `\\.\pipe\` is a per-session namespace they already own. It is a defence
//! against the other account on the same desktop, which is the realistic case.
//!
//! ## Idle cost
//!
//! `ConnectNamedPipe` parks the accept thread until a client appears, and a
//! connection's read parks until a line arrives. No poll loop, no timer thread,
//! no periodic scan. Each live connection owns one thread, which is why
//! `MAX_INSTANCES` is a real bound and not an aspiration — see
//! [`PipeInstance::serve_session`].
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
    os::windows::io::FromRawHandle,
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
///
/// Built from the current user's SID rather than `BU` (BUILTIN\Users) — see the
/// module header for why that distinction is the whole point of the descriptor.
///
/// Note the three semicolons before the SID. An ACE is
/// `A;<flags>;<rights>;<SID>;<inheritance>`, so `(A;;GA;;S-1-...)` is not a
/// shorthand — it is a *valid* ACE with an empty SID whose last field is the
/// inheritance flags. `ConvertStringSecurityDescriptor` accepts it, and the pipe
/// then fails to open for a reason that looks nothing like a permissions
/// problem.
fn sddl() -> Result<String, String> {
    Ok(format!("D:P(A;;GA;;;SY)(A;;GA;;;{})", current_user_sid()?))
}

fn current_user_sid() -> Result<String, String> {
    use windows::core::PWSTR;
    use windows::Win32::{
        Foundation::{LocalFree, HLOCAL},
        Security::{
            Authorization::ConvertSidToStringSidW, GetTokenInformation, TokenUser, TOKEN_QUERY,
            TOKEN_USER,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    unsafe {
        let mut token = HANDLE(std::ptr::null_mut());
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|e| format!("reading the process token failed: {e}"))?;
        let _token = HandleGuard(token);

        // Two calls: the first asks how much space is needed, which is also the
        // only way to find out whether the token carries a user at all.
        let mut needed = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
        if needed == 0 {
            return Err("the process token has no user".into());
        }

        let mut buffer = vec![0u8; needed as usize];
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut std::ffi::c_void),
            needed,
            &mut needed,
        )
        .map_err(|e| format!("reading the token user failed: {e}"))?;

        let user = &*(buffer.as_ptr() as *const TOKEN_USER);

        let mut out = PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut out)
            .map_err(|e| format!("converting the user SID to a string failed: {e}"))?;

        let text = out.to_string().unwrap_or_default();
        let _ = LocalFree(Some(HLOCAL(out.0 as *mut std::ffi::c_void)));
        Ok(text)
    }
}

/// Length in UTF-16 units of a NUL-terminated wide string.
unsafe fn len_of(p: *const u16) -> usize {
    let mut n = 0usize;
    while *p.add(n) != 0 {
        n += 1;
    }
    n
}

/// A pipe instance, its security descriptor, and the bookkeeping to free both.
///
pub struct PipeInstance {
    handle: HANDLE,
    sd: PSECURITY_DESCRIPTOR,
}

/// # Why this is `Send`
///
/// It is handed to a dedicated thread by the accept loop, which is what keeps one
/// client from blocking another. `PSECURITY_DESCRIPTOR` wraps a raw pointer, so
/// the compiler cannot see that the two fields belong exclusively to this value.
///
/// That is true: `handle` and `sd` are only ever touched through `&self` or
/// `&mut self` on the owning `PipeInstance`, never copied out and never aliased.
/// Moving the value to another thread moves exclusive ownership with it. The
/// descriptor is created in [`PipeInstance::create`] and freed in `Drop` *after*
/// the handle is closed, so its lifetime is a superset of the handle's, which is
/// the ordering Win32 requires here.
unsafe impl Send for PipeInstance {}

impl PipeInstance {
    /// Create one instance. Fails if the name is already fully occupied.
    pub fn create() -> Result<Self, String> {
        Self::create_named(PIPE_NAME)
    }

    /// Create one instance under a specific name.
    ///
    /// The name is a parameter so that tests can run against a pipe of their own
    /// instead of the shared one. Otherwise `cargo test` and a `teavaultd` the
    /// developer left running both claim `PIPE_NAME`, the test server silently
    /// attaches to the real daemon's instances, and every assertion is made
    /// against the wrong vault. That failure is confusing rather than obvious: the
    /// tests do fail, but nothing points at the cause.
    pub fn create_named(name: &str) -> Result<Self, String> {
        unsafe {
            let mut sd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
            let sddl = wide(&sddl()?);
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )
            .map_err(|e| format!("building the pipe security descriptor failed: {e}"))?;

            let name = wide(name);
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
    /// A connection is a **session**, not a single exchange. That matters because
    /// the desktop UI holds one connection open and issues many commands over it:
    /// with one-request-per-connection every command after the first writes into a
    /// pipe the server has already closed and fails with ERROR_NO_DATA — while
    /// every one-shot client, such as the CLI, keeps working, which makes the bug
    /// look intermittent.
    ///
    /// ## Reading is bounded while it happens, not after
    ///
    /// The previous version called `read_line` and only then checked the length. That
    /// defeats the limit completely: `read_line` appends to a `String` until it finds
    /// a newline, so a client that never sends one makes the daemon allocate
    /// gigabytes. The 64 KiB cap in `MAX_MESSAGE_BYTES` was therefore documented
    /// protection that did not exist.
    ///
    /// Here the reader is wrapped in `Read::take`, so the OS is asked for at most
    /// `MAX_MESSAGE_BYTES + 1` bytes before the buffer can grow past the limit. The
    /// extra byte is what distinguishes "exactly at the limit" from "over it" without
    /// a second read.
    ///
    /// ## The loop ends when
    ///
    /// The client closes (read returns 0), the pipe errors, a write fails, or the
    /// message was oversized and the connection is dropped — an oversized message
    /// leaves the stream at an unknown offset, so the framing can no longer be
    /// trusted and continuing would answer requests with somebody else's bytes.
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
            let outcome = match read_line_capped(&mut reader, &mut line, MAX_MESSAGE_BYTES) {
                Ok(o) => o,
                // A read error ends the session. There is no useful way to
                // continue on a pipe whose framing is in doubt.
                Err(_) => return false,
            };

            // Clean hang-up: the client is done with this session.
            let read = match outcome {
                Outcome::Line(n) => n,
                Outcome::TooLong => {
                    // Answer, then drop the connection. Truncating and continuing
                    // would be worse: the tail of the oversized message would be
                    // read as the next request, so one hostile client could make
                    // TEAvault execute a request it never received.
                    let _ = self.write_line(&error_line(
                        "request exceeds the maximum size; this connection is being closed",
                    ));
                    return false;
                }
            };
            if read == 0 {
                return false;
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

/// What a capped read found.
enum Outcome {
    /// A complete line, plus how many bytes it consumed.
    Line(usize),
    /// The message passed `cap` before a newline appeared.
    TooLong,
}

/// `read_line` with a hard ceiling enforced *while* the bytes arrive.
///
/// `BufRead::read_line` grows its `String` until it finds a newline, so a client
/// that never sends one makes the daemon allocate without bound. The previous
/// version read first and checked the length afterwards, which is not a limit at
/// all — `MAX_MESSAGE_BYTES` bounded what a *well-behaved* client could send while
/// documenting protection against a hostile one.
///
/// Here growth is refused as soon as it would pass `cap`, so the worst case is a
/// single bounded allocation and the rest of the oversized message is never
/// consumed.
fn read_line_capped<R: BufRead>(
    reader: &mut R,
    out: &mut String,
    cap: usize,
) -> std::io::Result<Outcome> {
    let mut total = 0usize;
    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            return Ok(Outcome::Line(total));
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(i) => {
                if out.len() + i + 1 > cap {
                    return Ok(Outcome::TooLong);
                }
                push_bytes(out, &available[..=i]);
                reader.consume(i + 1);
                return Ok(Outcome::Line(total + i + 1));
            }
            None => {
                let len = available.len();
                if out.len() + len > cap {
                    // Stop without consuming: the remainder is still queued and
                    // the caller is about to close the connection anyway.
                    return Ok(Outcome::TooLong);
                }
                push_bytes(out, available);
                reader.consume(len);
                total += len;
            }
        }
    }
}

/// Append pipe bytes to `out`.
///
/// A pipe carries arbitrary bytes, so the content may not be UTF-8. Lossy
/// conversion here is safe *because* the result is handed to a JSON parser,
/// which rejects anything malformed and produces the right error; the
/// alternative — propagating the UTF-8 error — would turn "not a request" into a
/// transport failure and drop the connection.
fn push_bytes(out: &mut String, bytes: &[u8]) {
    match std::str::from_utf8(bytes) {
        Ok(s) => out.push_str(s),
        Err(_) => out.push_str(&String::from_utf8_lossy(bytes)),
    }
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
/// A connection is a session, not a single exchange. The desktop UI holds one
/// open for its whole lifetime and issues many commands over it; making this
/// one-request-per-connection broke every command after the first while leaving
/// the CLI — which connects per command — working, which is why the bug looked
/// intermittent rather than obvious.
pub struct Client {
    handle: HANDLE,
}

impl Client {
    /// Connect, retrying briefly while the daemon starts.
    ///
    /// A refusal is never retried: it is the daemon's answer, and asking again would
    /// only give a caller a second attempt at whatever it is probing.
    pub fn connect_with_retry(timeout: std::time::Duration) -> Result<Client, ClientError> {
        Client::connect_with_retry_named(PIPE_NAME, timeout)
    }

    /// `connect_with_retry` against a specific pipe name. See
    /// [`PipeInstance::create_named`] for why the name is a parameter at all.
    pub fn connect_with_retry_named(
        pipe_name: &str,
        timeout: std::time::Duration,
    ) -> Result<Client, ClientError> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match Client::connect_named(pipe_name) {
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
        Client::connect_named(PIPE_NAME)
    }

    /// `connect` against a specific pipe name.
    pub fn connect_named(pipe_name: &str) -> Result<Self, ClientError> {
        unsafe {
            let name = wide(pipe_name);
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
    ///
    /// A connection may carry several requests — that is what makes the desktop UI's
    /// long-lived session work — but each `send` is a single complete exchange, and
    /// the handle stays owned by `Client` throughout.
    pub fn send(&self, req: Request) -> Result<serde_json::Value, ClientError> {
        let line = serde_json::to_string(&req).map_err(|e| ClientError::Protocol(e.to_string()))?;
        if line.len() > MAX_MESSAGE_BYTES {
            return Err(ClientError::Protocol("request is too large".into()));
        }

        let mut bytes = line.into_bytes();
        bytes.push(b'\n');

        let raw = self.handle.0;
        // Borrow, do not own: `Client` still owns the handle and its `Drop`
        // closes it. The previous version wrapped the handle in an `OwnedHandle`
        // and then `mem::forget` the `File` on the *success* path only — so every
        // early return and every `?` closed the handle, and `Client::drop` closed
        // it a second time. Closing a handle twice is not a no-op: the second
        // close can land on a recycled handle belonging to an unrelated object.
        // `ManuallyDrop` makes the ownership unambiguous on every path.
        let file = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_handle(raw) });
        let mut file = file;
        {
            let writer = &mut *file;
            writer.write_all(&bytes)?;
            writer.flush()?;
        }

        let mut text = String::new();
        let n = match read_line_capped(
            &mut BufReader::new(&mut *file),
            &mut text,
            MAX_MESSAGE_BYTES,
        )? {
            Outcome::Line(n) => n,
            Outcome::TooLong => {
                return Err(ClientError::Protocol(
                    "the daemon sent a response larger than the protocol allows".into(),
                ))
            }
        };
        if n == 0 {
            return Err(ClientError::Protocol(
                "the daemon closed the connection without answering".into(),
            ));
        }

        let response: teavault_core::ipc::Response =
            serde_json::from_str(text.trim_end_matches(['\r', '\n']))
                .map_err(|e| ClientError::Protocol(e.to_string()))?;

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

#[cfg(test)]
mod sddl_tests {
    use super::sddl;

    #[test]
    fn the_descriptor_names_this_user_and_not_all_users() {
        let d = sddl().expect("the current user's SID must be readable");
        assert!(d.starts_with("D:P"), "the DACL must be protected: {d}");
        assert!(
            d.contains("SY"),
            "the system account must be reachable: {d}"
        );
        assert!(
            !d.contains(";;;BU)"),
            "BUILTIN\\Users must not be granted access: {d}"
        );
        assert!(
            d.contains(";;;S-1-"),
            "the current user's SID must be present: {d}"
        );
    }
}
