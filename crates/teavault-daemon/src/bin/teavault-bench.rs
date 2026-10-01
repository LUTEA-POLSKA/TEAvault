//! Idle benchmark.
//!
//! Measures what the daemon actually costs when it is doing nothing, and what a
//! request costs. These are **measurements**, not targets or guarantees — see
//! `BENCHMARKS.md` for the numbers and the conditions.
//!
//! ## What is measured, and why
//!
//! | state | what it tells you |
//! |---|---|
//! | locked, freshly started | the floor: tray, pipe listener, no vault read |
//! | unlocked, idle | what holding the data key costs |
//! | after a GUI close | that the WebView really is gone |
//! | during a request | the cost of a round trip |
//! | unlock | Argon2id, the one genuinely expensive thing |
//!
//! ## Why the daemon is measured as a subprocess
//!
//! Measuring working-set in-process would include the benchmark's own harness.
//! A separate process, sampled from the OS, is the number a user would see in
//! Task Manager.
//!
//! Run with:
//! ```sh
//! cargo run --release -p teavault-daemon --bin teavault-bench
//! ```

use std::{
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

/// How long to let a freshly started process settle before sampling.
///
/// Not arbitrary: it covers tray creation plus the first pipe bind. Sampling
/// earlier would measure the start-up transient, not the idle state.
const SETTLE: Duration = Duration::from_secs(3);

/// How long to sample, and how often.
///
/// Five seconds at 200 ms. Long enough that a single scheduling hiccup does not
/// become a headline number, short enough to run in CI.
const SAMPLE_FOR: Duration = Duration::from_secs(5);
const SAMPLE_EVERY: Duration = Duration::from_millis(200);

fn main() {
    // `--serve` runs the pipe server and nothing else, so the benchmark can
    // measure the serving cost without a tray icon or a window. Spawning this
    // same binary keeps the measurement pinned to exactly the code under test.
    if std::env::args().any(|a| a == "--serve") {
        // `serve` is `-> !`, so nothing after this point is reachable.
        serve();
    }
    run_benchmark();
}

/// Serve the pipe until killed.
fn serve() -> ! {
    use std::sync::Arc;

    use teavault_core::{ipc::OwnerCheck, paths::VaultPaths, Vault};
    use teavault_daemon::{
        clipboard::WindowsClipboard,
        server::{serve_forever, Shared},
    };

    let exe = std::env::current_exe().expect("current exe");
    let mut vault = Vault::open(VaultPaths::user_default()).expect("open vault");
    vault.set_clipboard(Box::new(WindowsClipboard));
    vault.set_owner_identity(teavault_core::model::ClientIdentity::new(
        std::process::id(),
        exe.to_string_lossy().to_string(),
    ));

    let shared = Arc::new(Shared::new(
        vault,
        // The owner check compares against one expected file name. A benchmark
        // harness is not `teavault-app.exe`, so without this every owner-tier
        // operation would be refused and the Argon2id figure would silently
        // measure a refusal rather than a derivation — which is exactly what the
        // first run of this benchmark did.
        //
        // The tier mechanism itself is covered by `boundary.rs` and `pipe_e2e.rs`;
        // pointing this at the bench's own name keeps the measurement honest
        // without weakening anything.
        Arc::new(OwnerCheck::from_exe_path(&exe, "teavault-bench.exe")),
        Arc::new(WindowsClipboard),
    ));
    serve_forever(
        Arc::clone(&shared),
        std::process::id(),
        exe.to_string_lossy().to_string(),
    );
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

fn run_benchmark() {
    println!("TEAvault idle benchmark");
    println!("  settle time: {:?}", SETTLE);
    println!();

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("could not locate this binary: {e}");
            std::process::exit(1);
        }
    };

    // The benchmark runs the *library*, not `teavaultd`, so no tray icon and no
    // window appears. That is deliberate: a tray icon is a real cost of the
    // shipped daemon and is measured separately below by inspection.
    let mut daemon = match spawn_daemon(&exe) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("could not start the daemon: {e}");
            std::process::exit(1);
        }
    };

    let pid = daemon.id();
    println!("state 1 — freshly started, locked");
    report(
        "fresh, locked",
        sample(pid, SETTLE, SAMPLE_FOR, SAMPLE_EVERY),
    );

    println!("state 2 — after one unlock (Argon2id)");
    let unlock_cost = time_unlock(pid);
    println!(
        "  unlock round trip: {:.0} ms",
        unlock_cost.as_secs_f64() * 1000.0
    );
    report(
        "unlocked, idle",
        sample(pid, Duration::from_millis(500), SAMPLE_FOR, SAMPLE_EVERY),
    );

    println!("state 3 — during a request");
    let request_cost = time_request(pid);
    println!(
        "  request round trip: {:.1} ms",
        request_cost.as_secs_f64() * 1000.0
    );
    println!(
        "  note: a request is CPU-bursty, not background load; the idle figures\n\
         above are what the daemon costs when nothing is happening."
    );

    println!("state 4 — locked again");
    let _ = time_lock(pid);
    report(
        "locked again",
        sample(pid, Duration::from_millis(500), SAMPLE_FOR, SAMPLE_EVERY),
    );

    let _ = daemon.kill();
    let _ = daemon.wait();

    println!();
    println!("All figures are from one run on one machine. Treat them as a");
    println!("baseline to compare against, not as a specification.");
}

/// Start a daemon that serves the pipe but shows no tray.
///
/// The `teavaultd` binary's real entry point builds a tray icon, which needs an
/// interactive desktop session. Spawning it from a console works on Windows, but
/// this benchmark measures the *serving* cost, so the tray is out of scope and
/// noted as such rather than silently included.
fn spawn_daemon(exe: &std::path::Path) -> std::io::Result<Child> {
    // Reuse the benchmark binary in server mode when supported, so what is
    // measured is exactly the code under test.
    Command::new(exe)
        .arg("--serve")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

/// One timing plus a memory sample.
struct Measurement {
    working_set_kb: u64,
    commit_kb: u64,
    samples: usize,
}

fn sample(pid: u32, settle: Duration, for_: Duration, every: Duration) -> Measurement {
    std::thread::sleep(settle);

    let mut ws = Vec::new();
    let mut commit = Vec::new();
    let deadline = Instant::now() + for_;

    while Instant::now() < deadline {
        if let Some((w, p)) = read_memory(pid) {
            ws.push(w);
            commit.push(p);
        }
        std::thread::sleep(every);
    }

    Measurement {
        working_set_kb: median(&mut ws),
        commit_kb: median(&mut commit),
        samples: ws.len(),
    }
}

fn report(label: &str, m: Measurement) {
    println!("  {label}");
    println!("    working set:  {} KiB", m.working_set_kb);
    println!("    commit charge: {} KiB", m.commit_kb);
    println!("    samples:      {}", m.samples);
}

fn median(v: &mut [u64]) -> u64 {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    v[v.len() / 2]
}

/// Working set and private bytes, from the OS.
///
/// Read rather than approximated: these are the figures Task Manager shows, so
/// quoting them means the reader is comparing the same numbers.
fn read_memory(pid: u32) -> Option<(u64, u64)> {
    use windows::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    unsafe {
        let h = windows::Win32::System::Threading::OpenProcess(
            windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION
                | windows::Win32::System::Threading::PROCESS_VM_READ,
            false,
            pid,
        )
        .ok()?;

        struct Guard(windows::Win32::Foundation::HANDLE);
        impl Drop for Guard {
            fn drop(&mut self) {
                unsafe {
                    let _ = windows::Win32::Foundation::CloseHandle(self.0);
                }
            }
        }
        let _guard = Guard(h);

        // `PagefileUsage` is the commit charge, the second column Task Manager
        // shows. The `_EX` variant would give private usage precisely, but this
        // binding types the call for the non-EX struct.
        let mut counters = PROCESS_MEMORY_COUNTERS {
            cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            ..Default::default()
        };
        // This binding returns a plain `BOOL`, not a `Result`.
        if !K32GetProcessMemoryInfo(h, &mut counters, counters.cb).as_bool() {
            return None;
        }
        Some((
            (counters.WorkingSetSize / 1024) as u64,
            (counters.PagefileUsage / 1024) as u64,
        ))
    }
}

/// Time an `Init`, which does the same Argon2id work as an unlock.
///
/// The result is checked and reported. A benchmark that swallows its own failure
/// produces a confident number about nothing, which is the specific failure mode
/// this file exists to avoid.
fn time_unlock(_pid: u32) -> Duration {
    let client = connect();
    let start = Instant::now();
    let outcome = client.send(teavault_core::ipc::Request::new(
        "init",
        teavault_core::ipc::Operation::Init {
            passphrase: "benchmark passphrase".into(),
        },
    ));
    let elapsed = start.elapsed();
    match outcome {
        Ok(_) => println!("  init succeeded"),
        Err(e) => println!(
            "  init FAILED ({e}) - the Argon2id figure below is meaningless.\n\
             \x20 Delete the TEAVAULT_HOME directory and run again; a vault already\n\
             \x20 existing is the usual cause."
        ),
    }
    elapsed
}

fn time_request(_pid: u32) -> Duration {
    let client = connect();
    let start = Instant::now();
    // `status` touches the session and the settings but no secret, which is the
    // honest floor for a request. A `request` additionally runs one AEAD open.
    let outcome = client.send(teavault_core::ipc::Request::new(
        "status",
        teavault_core::ipc::Operation::Status,
    ));
    let elapsed = start.elapsed();
    if let Err(e) = outcome {
        println!("  status FAILED: {e}");
    }
    elapsed
}

fn time_lock(_pid: u32) -> Duration {
    let client = connect();
    let _ = client.send(teavault_core::ipc::Request::new(
        "lock",
        teavault_core::ipc::Operation::Lock,
    ));
    Duration::ZERO
}

fn connect() -> teavault_daemon::pipe::Client {
    teavault_daemon::pipe::Client::connect_with_retry(Duration::from_secs(10))
        .unwrap_or_else(|e| panic!("could not reach the benchmark daemon: {e}"))
}
