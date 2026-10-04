//! The pipe accept loop and the state the daemon's threads share.
//!
//! This is where transport meets core, and the only place that does. Everything
//! policy-shaped lives in [`teavault_core::ipc::dispatch`]; everything
//! OS-shaped lives in [`crate::pipe`]. This module owns neither — it wires them
//! together and keeps the vault behind a mutex.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use teavault_core::{
    clipboard::Clipboard,
    ipc::{
        dispatch::{Caller, Dispatcher},
        OwnerCheck,
    },
    model::ClientIdentity,
    Vault,
};

use crate::pipe::{self, PipeInstance};

/// State shared between the tray, the pipe server and the deadline thread.
pub struct Shared {
    pub vault: Mutex<Vault>,
    pub owner: Arc<OwnerCheck>,
    pub clipboard: Arc<dyn Clipboard>,
    /// A copied secret waiting for its clear deadline: `(entry id, value, due)`.
    ///
    /// Holds the plaintext, which is the cost of being able to clear
    /// conditionally rather than blindly.
    pending_clear: Mutex<Option<(String, String, Instant)>>,
    clear_signal: Condvar,
    quitting: AtomicBool,
}

impl Shared {
    pub fn new(vault: Vault, owner: Arc<OwnerCheck>, clipboard: Arc<dyn Clipboard>) -> Self {
        Self {
            vault: Mutex::new(vault),
            owner,
            clipboard,
            pending_clear: Mutex::new(None),
            clear_signal: Condvar::new(),
            quitting: AtomicBool::new(false),
        }
    }

    /// Run `f` with the vault locked.
    ///
    /// A poisoned mutex is recovered rather than propagated: the vault's own
    /// invariants are restored on every operation that mutates it, and refusing
    /// to start after an unrelated panic would be worse than carrying on.
    pub fn with_vault<T>(&self, f: impl FnOnce(&mut Vault) -> T) -> T {
        let mut guard = self
            .vault
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&mut guard)
    }

    pub fn is_quitting(&self) -> bool {
        self.quitting.load(Ordering::SeqCst)
    }

    pub fn quit(&self) {
        self.quitting.store(true, Ordering::SeqCst);
        self.clear_signal.notify_all();
    }

    /// Arm the one-shot clipboard clear.
    ///
    /// One wake-up per copied key, then the deadline thread parks again. With
    /// clearing switched off (seconds == 0) nothing is armed — the UI warns
    /// about that choice rather than this silently doing nothing.
    fn schedule_clear(&self, seconds: u32) {
        if seconds == 0 {
            return;
        }
        let mut pending = self.pending_clear.lock().unwrap_or_else(|p| p.into_inner());
        // The value is already known to the clipboard; keeping it here is what
        // lets the clear be conditional.
        let entry = pending
            .as_ref()
            .map(|(id, _, _)| id.clone())
            .unwrap_or_default();
        let value = self.clipboard.get().unwrap_or(None).unwrap_or_default();
        *pending = Some((
            entry,
            value,
            Instant::now() + Duration::from_secs(seconds as u64),
        ));
        drop(pending);
        self.clear_signal.notify_all();
    }
}

/// Serve clients until [`Shared::quit`] is called.
///
/// Blocking throughout: `ConnectNamedPipe` parks until a client appears, and a
/// read parks until a line arrives. This is the whole idle story — a daemon with
/// no clients does no work and is not scheduled.
pub fn serve_forever(
    shared: Arc<Shared>,
    own_pid: u32,
    own_path: String,
) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("teavault-pipe".into())
        .spawn(move || accept_loop(&shared, own_pid, &own_path, pipe::PIPE_NAME))
        .expect("the pipe thread must start")
}

/// Serve clients on `pipe_name`, on its own thread.
///
/// The production path is [`serve_forever`], which owns the well-known
/// [`pipe::PIPE_NAME`]. This variant exists so an integration test can bind a
/// private pipe instead of the real one — two servers on one name would mean
/// the second silently never accepts.
///
/// Returns immediately, so a caller that has just built a [`Shared`] does not
/// block before it can hand that vault over.
pub fn serve_pipe_named(
    shared: Arc<Shared>,
    own_pid: u32,
    own_path: String,
    pipe_name: &str,
) -> thread::JoinHandle<()> {
    let pipe_name = pipe_name.to_owned();
    thread::Builder::new()
        .name("teavault-pipe-test".into())
        .spawn(move || accept_loop(&shared, own_pid, &own_path, &pipe_name))
        .expect("the pipe thread must start")
}

fn accept_loop(shared: &Arc<Shared>, own_pid: u32, own_path: &str, pipe_name: &str) {
    loop {
        if shared.is_quitting() {
            return;
        }

        let instance = match PipeInstance::create_named(&pipe_name) {
            Ok(i) => i,
            Err(e) => {
                eprintln!("teavaultd: pipe: {e}");
                // Do not spin on a permanent failure.
                thread::sleep(Duration::from_secs(5));
                continue;
            }
        };

        if instance.connect().is_err() {
            continue;
        }

        let caller = match caller_for(shared, &instance, own_pid, own_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("teavaultd: pipe: {e}");
                continue;
            }
        };

        // One thread per connection. `serve_session` parks for as long as the
        // client stays connected, so serving it inline would let a single
        // long-lived client — the UI, which holds its connection open — block
        // every other client from being accepted at all.
        let worker_shared = Arc::clone(shared);
        if thread::Builder::new()
            .name("teavault-conn".into())
            .spawn(move || serve_connection(worker_shared, instance, caller))
            .is_err()
        {
            eprintln!("teavaultd: pipe: could not start a worker thread");
        }
    }
}

/// Handle one accepted connection until the client disconnects.
///
/// The caller is already resolved and immutable here: the tier came from the
/// image path the kernel reported, so nothing in this loop can change what this
/// client is allowed to do.
fn serve_connection(shared: Arc<Shared>, instance: PipeInstance, caller: Caller) {
    let mut was_copy = false;
    let served = instance.serve_session(&mut |line| {
        // A `copy` needs the deadline thread armed. Detected from the request,
        // because the response deliberately says nothing about which operation
        // ran.
        was_copy = request_op(line).as_deref() == Some("copy");
        shared.with_vault(|v| {
            let mut d = Dispatcher::new(v, &shared.owner);
            serde_json::to_string(&d.handle_line(&caller, line)).unwrap_or_default()
        })
    });

    if served && was_copy {
        let seconds = shared.with_vault(|v| v.settings().clipboard_clear_seconds);
        shared.schedule_clear(seconds);
    }
}

/// The kernel's answer to "who is calling", turned into a caller.
///
/// A request the daemon issues to itself is recognised by PID and treated as
/// the owner identity, which is what lets the tray and the `--once` path reach
/// owner operations without a credential.
fn caller_for(
    shared: &Shared,
    instance: &PipeInstance,
    own_pid: u32,
    own_path: &str,
) -> Result<Caller, String> {
    let identity = instance.client_identity()?;
    let identity = if identity.pid == own_pid {
        ClientIdentity::new(own_pid, own_path.to_string())
    } else {
        identity
    };
    let tier = shared.owner.classify(&identity.image_path);
    Ok(Caller { identity, tier })
}

/// The `op` field of a request line, without fully parsing it.
fn request_op(line: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()?
        .get("op")?
        .as_str()
        .map(str::to_string)
}

/// Park until a clipboard clear is due.
///
/// `Condvar::wait_timeout` blocks in the OS and wakes on a signal or the
/// deadline. With no copy pending the predicate is false and the wait is
/// effectively indefinite, so an idle daemon does not wake for this at all.
pub fn spawn_deadline_thread(shared: Arc<Shared>) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("teavault-clipboard-deadline".into())
        .spawn(move || loop {
            if shared.is_quitting() {
                return;
            }

            let mut pending = shared
                .pending_clear
                .lock()
                .unwrap_or_else(|p| p.into_inner());

            let Some((_, _, due)) = pending.as_ref() else {
                let (guard, _) = shared
                    .clear_signal
                    .wait_timeout(pending, Duration::from_secs(3600))
                    .unwrap_or_else(|p| p.into_inner());
                pending = guard;
                continue;
            };

            let now = Instant::now();
            if *due <= now {
                let (entry_id, expected, _) = pending.take().expect("checked above");
                drop(pending);

                let cleared = shared
                    .clipboard
                    .clear_if_unchanged(&expected)
                    .unwrap_or(false);
                if cleared {
                    shared.with_vault(|v| v.note_clipboard_cleared(&entry_id));
                }
                continue;
            }

            let wait = due.saturating_duration_since(now);
            let (guard, _) = shared
                .clear_signal
                .wait_timeout(pending, wait)
                .unwrap_or_else(|p| p.into_inner());
            pending = guard;
        })
        .expect("the deadline thread must start")
}

/// Whether the daemon's pipe appears to be listening.
pub fn pipe_is_listening() -> bool {
    let _ = pipe::PIPE_NAME;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_line_yields_its_op() {
        assert_eq!(
            request_op(r#"{"v":1,"id":"1","op":"list"}"#).as_deref(),
            Some("list")
        );
        assert_eq!(request_op("not json"), None);
        assert_eq!(request_op(r#"{"v":1}"#), None);
    }

    #[test]
    fn a_copy_op_is_detected_and_others_are_not() {
        assert_eq!(
            request_op(r#"{"v":1,"id":"1","op":"copy","entry":"A"}"#).as_deref(),
            Some("copy")
        );
        assert_ne!(
            request_op(r#"{"v":1,"id":"1","op":"request","entry":"A"}"#).as_deref(),
            Some("copy")
        );
    }
}
