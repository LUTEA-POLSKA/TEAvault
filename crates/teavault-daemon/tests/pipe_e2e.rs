//! End-to-end tests over a real Windows named pipe.
//!
//! These start the actual pipe server and connect with the actual client, so
//! they cover the parts unit tests cannot: the DACL, the framing, the
//! `GetNamedPipeClientProcessId` identity resolution, and the tier that comes out
//! of it.
//!
//! They run inside a single process, so the client is `teavaultd`'s own test
//! binary. That is deliberate and it has a consequence worth stating: the tier
//! check compares the client image path against the directory the daemon expects,
//! and a test binary is not `teavault-app.exe`. So these tests exercise the
//! **agent** tier, and the owner tier is covered in `teavault-core`'s
//! `boundary.rs`, where the tier is supplied directly. Nothing here claims to
//! test owner-tier behaviour over a pipe.

use std::{
    io::{BufRead, BufReader, Write},
    os::windows::io::FromRawHandle,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
};

use teavault_core::{
    clipboard::MemoryClipboard,
    ipc::{Operation, OwnerCheck, Request},
    model::{GrantMode, Visibility},
    paths::VaultPaths,
    Vault,
};
use teavault_daemon::{pipe::PIPE_NAME, server::serve_forever, Shared};

const PASS: &[u8] = b"an e2e test passphrase";

/// An entry no test ever grants, so refusal tests do not depend on test order.
const NEVER_GRANTED: &str = "NEVER_GRANTED_API_KEY";

/// An entry reserved for the deny test.
///
/// The deny tests need a *standing deny* left in place, and a deny removes the
/// entry from `list` for that client. Putting it on a shared entry poisoned
/// whichever test happened to list next — which looked like a flaky assertion
/// until the cause was traced. Its own entry keeps the shared vault in a known
/// state without cleanup.
const DENIED: &str = "DENIED_API_KEY";

/// The one running server.
///
/// The pipe name is global, so two servers would collide, and the accept loop
/// serves one client at a time. Tests therefore share a server and take
/// [`lock_server`] to make sure only one client is connected.
static SERVER: OnceLock<Arc<Shared>> = OnceLock::new();
static LOCK: Mutex<()> = Mutex::new(());

/// Start the server if it is not already running, and take the client lock.
fn lock_server() -> (Arc<Shared>, MutexGuard<'static, ()>) {
    let guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let shared = SERVER.get_or_init(|| {
        // Both the `TempDir` *and* its path are leaked: dropping the `TempDir`
        // would delete the vault out from under the running server.
        let dir: &'static tempfile::TempDir =
            Box::leak(Box::new(tempfile::tempdir().expect("temp dir")));
        let root = dir.path();

        let mut vault = Vault::open(VaultPaths::new(root)).expect("open vault");
        vault.create(PASS).expect("create vault");
        vault
            .create_entry(
                "OPENAI_API_KEY",
                "OpenAI",
                "OpenAI",
                None,
                vec!["llm".into()],
                Visibility::Discoverable,
                teavault_core::crypto::SecretString::new(b"sk-e2e-not-a-real-key".to_vec()),
            )
            .expect("create entry");
        vault
            .create_entry(
                NEVER_GRANTED,
                "Never granted",
                "OpenAI",
                None,
                vec![],
                Visibility::Discoverable,
                teavault_core::crypto::SecretString::new(b"sk-never-released".to_vec()),
            )
            .expect("create entry");
        vault
            .create_entry(
                DENIED,
                "Denied",
                "OpenAI",
                None,
                vec![],
                Visibility::Discoverable,
                teavault_core::crypto::SecretString::new(b"sk-denied-secret".to_vec()),
            )
            .expect("create entry");

        // Expect this test binary's own path, so the client's identity comes from
        // the kernel rather than being fabricated.
        let exe = std::env::current_exe().expect("current exe");
        let owner = Arc::new(OwnerCheck::from_exe_path(&exe, "teavault-app.exe"));

        vault.set_clipboard(Box::new(MemoryClipboard::new()));
        vault.set_owner_identity(teavault_core::model::ClientIdentity::new(
            std::process::id(),
            exe.to_string_lossy().to_string(),
        ));

        let shared = Arc::new(Shared::new(vault, owner, Arc::new(MemoryClipboard::new())));
        serve_forever(
            Arc::clone(&shared),
            std::process::id(),
            exe.to_string_lossy().to_string(),
        );
        shared
    });
    (Arc::clone(shared), guard)
}

/// Connect, retrying briefly while the server binds the pipe.
fn connect() -> TestClient {
    let mut last = String::new();
    for _ in 0..60 {
        match TestClient::connect() {
            Ok(c) => return c,
            Err(e) => {
                last = e;
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
    // The pipe name is global, so a real `teavaultd` running alongside the tests
    // makes this suite fail with a bare timeout. Say so, rather than leaving a
    // developer to guess.
    panic!(
        "could not connect to {PIPE_NAME} after 3s: {last}\n\
         \x20 Another TEAvault daemon is probably already running and holding the\n\
         \x20 pipe. Quit it (tray icon, or `Stop-Process -Name teavaultd`) and re-run."
    );
}

/// A blocking pipe client, mirroring what the CLI does.
struct TestClient {
    handle: windows::Win32::Foundation::HANDLE,
}

impl TestClient {
    fn connect() -> Result<Self, String> {
        use windows::{
            core::PCWSTR,
            Win32::Storage::FileSystem::{
                CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, OPEN_EXISTING,
                PIPE_ACCESS_DUPLEX,
            },
        };
        unsafe {
            let name: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
            let handle = CreateFileW(
                PCWSTR(name.as_ptr()),
                PIPE_ACCESS_DUPLEX.0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
            .map_err(|_| format!("CreateFileW: {}", std::io::Error::last_os_error()))?;
            Ok(Self { handle })
        }
    }

    fn send_raw(&self, line: &str) -> String {
        let mut bytes = line.as_bytes().to_vec();
        bytes.push(b'\n');
        let file = std::fs::File::from(unsafe {
            std::os::windows::io::OwnedHandle::from_raw_handle(self.handle.0)
        });
        let mut writer = &file;
        writer.write_all(&bytes).expect("write request");
        writer.flush().expect("flush");

        let mut reader = BufReader::new(&file);
        let mut response = String::new();
        let n = reader.read_line(&mut response).expect("read response");
        assert!(n > 0, "the daemon closed the connection without answering");
        std::mem::forget(file);
        response.trim_end_matches(['\r', '\n']).to_string()
    }

    fn send(&self, req: Request) -> Result<serde_json::Value, teavault_core::ipc::ErrorBody> {
        let line = serde_json::to_string(&req).expect("serialise request");
        let resp: teavault_core::ipc::Response =
            serde_json::from_str(&self.send_raw(&line)).expect("parse response");
        match resp.error {
            None => Ok(resp.result.expect("checked")),
            Some(e) => Err(e),
        }
    }
}

impl Drop for TestClient {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

fn send(op: Operation) -> Result<serde_json::Value, teavault_core::ipc::ErrorBody> {
    connect().send(Request::new("t", op))
}

#[test]
fn one_connection_serves_many_commands() {
    // The regression this pins: the transport is a *session*, not one request
    // per connection. The desktop UI holds a single connection open and issues
    // every command over it, so one-request-per-connection made every call
    // after the first fail with ERROR_NO_DATA (os error 233) — while the CLI,
    // which opens a fresh connection each time, kept working perfectly. That
    // asymmetry is what made it look intermittent.
    let (_shared, _guard) = lock_server();
    let client = connect();

    for i in 1..=12 {
        let out = client
            .send(Request::new("t", Operation::Status))
            .unwrap_or_else(|e| panic!("request {i} on a reused connection failed: {e:?}"));
        assert_eq!(out["protocol"], 1, "response {i} was not the status reply");
    }

    // Mixing operations on one connection must work too.
    let listed = client
        .send(Request::new("t", Operation::List { provider: None }))
        .expect("list after several status calls");
    assert!(listed["entries"].as_array().is_some_and(|e| !e.is_empty()));

    client
        .send(Request::new("t", Operation::Lock))
        .expect("lock on a reused connection");
    assert_eq!(
        client
            .send(Request::new("t", Operation::Status))
            .expect("status after lock")["locked"],
        true
    );

    // Leave the shared vault unlocked for the other tests.
    _shared.with_vault(|v| v.unlock(PASS).expect("re-unlock"));
}

#[test]
fn a_blank_line_is_answered_rather_than_desynchronising_the_session() {
    // Every line written must produce exactly one line read back. Silently
    // ignoring a blank line would leave the client blocked on a read that never
    // gets satisfied, and the next response it *does* read would be the answer
    // to its following request — off by one, silently.
    let (_shared, _guard) = lock_server();
    let client = connect();

    let first: teavault_core::ipc::Response =
        serde_json::from_str(&client.send_raw("")).expect("a response, not a hang");
    assert!(
        first.error.is_some(),
        "a blank line should be refused, not silently dropped"
    );

    let out = client
        .send(Request::new("t", Operation::Status))
        .expect("status after a blank line");
    assert_eq!(out["protocol"], 1, "the session is still in sync");
}

#[test]
fn status_works_over_a_real_pipe() {
    let (_shared, _guard) = lock_server();
    let out = send(Operation::Status).expect("status");
    assert_eq!(out["locked"], false);
    assert_eq!(out["protocol"], 1);

    // `entry_count` is the owner's total; `list` is what *this* client may see.
    // The strict inequality is deliberate: the deny test has left a standing deny
    // in place, and a denied entry is counted but not listed. Asserting the
    // relationship rather than a hard-coded total means adding a fixture entry
    // cannot silently break this.
    let counted = out["entry_count"].as_u64().expect("entry_count");
    let listed = send(Operation::List { provider: None }).expect("list");
    let visible = listed["entries"].as_array().expect("entries").len() as u64;
    assert!(
        counted > visible,
        "the total ({counted}) should exceed the visible list ({visible}), \
         because a denied entry is counted but not listed"
    );
}

#[test]
fn list_over_a_real_pipe_never_returns_a_secret() {
    let (_shared, _guard) = lock_server();
    let out = send(Operation::List { provider: None }).expect("list");
    let text = out.to_string();
    assert!(text.contains("OPENAI_API_KEY"));
    assert!(!text.contains("sk-e2e-not-a-real-key"));
}

#[test]
fn a_request_without_a_grant_is_refused_over_the_pipe() {
    let (_shared, _guard) = lock_server();
    // `NEVER_GRANTED` exists precisely so this test does not depend on no other
    // test having created a grant for `OPENAI_API_KEY`.
    let err = send(Operation::Request {
        entry: NEVER_GRANTED.into(),
        purpose: None,
    })
    .expect_err("must be refused");
    assert_eq!(err.code, "needs_confirmation");
    assert!(err.request_id.is_some());
}

#[test]
fn an_owner_only_operation_is_refused_over_the_pipe() {
    // This test binary is not `teavault-app.exe`, so the tier resolves to Agent
    // and every owner operation must be refused. This is the check that stops
    // any local process from reaching vault administration.
    let (_shared, _guard) = lock_server();
    for op in [
        Operation::Access,
        Operation::Audit { limit: 10 },
        Operation::Delete {
            entry: "OPENAI_API_KEY".into(),
        },
        Operation::Revoke {
            grant_id: "whatever".into(),
        },
    ] {
        let err = send(op).expect_err("owner-only op must be refused");
        assert_eq!(
            err.code, "operation_not_allowed",
            "expected a tier refusal, got {err:?}"
        );
    }
}

#[test]
fn a_malformed_line_is_refused_without_killing_the_server() {
    let (_shared, _guard) = lock_server();

    // The protocol is one request per connection, so each junk line gets its
    // own client. Sending several lines on one connection is a protocol error,
    // not something to assert against here.
    for junk in ["not json", "{}", "[]", "null", "7"] {
        let response: teavault_core::ipc::Response =
            serde_json::from_str(&connect().send_raw(junk)).expect("a response, not a hang");
        assert!(response.error.is_some(), "{junk:?} should be refused");
    }

    // The server survived all of it.
    assert!(connect().send(Request::new("t", Operation::Status)).is_ok());
}

#[test]
fn locking_over_the_pipe_stops_further_reads() {
    let (shared, _guard) = lock_server();
    assert_eq!(send(Operation::Status).unwrap()["locked"], false);
    send(Operation::Lock).expect("lock");
    assert_eq!(send(Operation::Status).unwrap()["locked"], true);

    let err = send(Operation::List { provider: None }).expect_err("locked");
    assert_eq!(err.code, "vault_locked");

    // Restore state for the other tests, which share this server.
    shared.with_vault(|v| v.unlock(PASS).expect("re-unlock"));
}

#[test]
fn a_granted_request_releases_the_key_over_the_pipe() {
    let (shared, _guard) = lock_server();
    let identity = teavault_core::model::ClientIdentity::new(
        std::process::id(),
        std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .to_string(),
    );
    let entry_id = shared.with_vault(|v| v.resolve_entry_id("OPENAI_API_KEY").expect("entry id"));
    shared.with_vault(|v| {
        v.create_grant(
            &identity,
            &entry_id,
            GrantMode::AlwaysAllow { expires_at: None },
        )
        .expect("grant");
    });

    let out = send(Operation::Request {
        entry: "OPENAI_API_KEY".into(),
        purpose: None,
    })
    .expect("request with a grant");
    assert_eq!(out["value"], "sk-e2e-not-a-real-key");
}

#[test]
fn a_denied_client_is_refused_even_with_an_earlier_grant() {
    let (shared, _guard) = lock_server();
    let identity = teavault_core::model::ClientIdentity::new(
        std::process::id(),
        std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .to_string(),
    );
    let entry_id = shared.with_vault(|v| v.resolve_entry_id(DENIED).expect("entry id"));

    shared.with_vault(|v| {
        v.create_grant(
            &identity,
            &entry_id,
            GrantMode::AlwaysAllow { expires_at: None },
        )
        .expect("grant");
        v.grant_for_fingerprint(&entry_id, &identity.fingerprint(), "test", GrantMode::Deny)
            .expect("deny");
    });

    let err = send(Operation::Request {
        entry: DENIED.into(),
        purpose: None,
    })
    .expect_err("denied");
    assert_eq!(err.code, "denied_by_user");
}

#[test]
fn a_denied_entry_disappears_from_listing_for_that_client() {
    // The consequence of a standing deny, and the reason the deny test needs its
    // own entry: a denied entry is not listed, so a deny on a shared entry
    // silently changes what every other test sees. This test pins that
    // behaviour *and* proves the shared entries are unaffected.
    let (_shared, _guard) = lock_server();
    let out = send(Operation::List { provider: None }).expect("list");
    let text = out.to_string();
    assert!(!text.contains(DENIED), "a denied entry must not be listed");
    assert!(
        text.contains("OPENAI_API_KEY"),
        "other entries must be unaffected"
    );
}
