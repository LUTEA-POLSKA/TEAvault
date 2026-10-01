# Benchmarks

**These are measurements from one machine on one day. They are not targets, not
guarantees, and not a specification.** They are a baseline to compare a future
change against. Re-run them before claiming an improvement.

Reproduce with:

```sh
cargo run --release -p teavault-daemon --bin teavault-bench
```

The benchmark deletes and recreates its vault directory (`TEAVAULT_HOME`, or
`%LOCALAPPDATA%\TEAvault` by default). **Do not point it at a real vault.**

## Conditions

| | |
|---|---|
| CPU | Intel Core i7-4790 @ 3.60 GHz (Haswell, AVX2) |
| RAM | 16 GB |
| OS | Windows 11 |
| build | `--release` (`opt-level = "z"`, LTO, one codegen unit) |
| vault | 2 entries, so `list` and `status` do real work |
| sampling | median of 25 samples, 200 ms apart, after a 3 s settle |

`working set` is `WorkingSetSize` and `commit charge` is `PagefileUsage`, both read
from the OS via `K32GetProcessMemoryInfo` — the same source Task Manager uses, so
the numbers are comparable.

## Results

| state | working set | commit charge |
|---|---|---|
| freshly started, locked | **5 608 KiB** (5.5 MiB) | 1 156 KiB |
| unlocked, idle | **5 864 KiB** (5.7 MiB) | 1 176 KiB |
| locked again | **5 900 KiB** (5.8 MiB) | 1 188 KiB |

**Holding an unlocked vault costs about 250 KiB.** That is the data key, the
decrypted index and the Argon2id block allocation that has not been returned to
the OS — a real figure, and a small one.

### Operation timings

| operation | time |
|---|---|
| Argon2id unlock (19 MiB, t=2, p=1) | **~100 ms** |
| request round trip (`status`) | **~0.8 ms** |

The unlock is the only genuinely expensive operation, and it is expensive on
purpose: it is what makes an offline passphrase search costly. The settings screen
shows the parameters before you commit to typing one.

## What is *not* included

Stating this precisely, because a benchmark that quietly omits the expensive part
is worse than none:

- **The tray icon.** The benchmark runs the pipe server only. `teavaultd`'s real
  entry point also creates a `Shell_NotifyIcon` icon and runs a message pump,
  which adds a small amount of memory and a window station. Not measured here.
- **The desktop UI.** A Tauri window with a WebView2 instance costs far more than
  the daemon — typically tens of MiB. That is the reason it is a separate process
  with no permanent window, and it is not measured because it is not an idle cost:
  closing the window destroys the browser engine.
- **The `msvcrt`-level floor.** A bare Rust process on Windows is around 1–2 MiB
  before any work. Most of the 5.5 MiB above is the Rust runtime, the crypto
  tables and the loaded DLLs, not TEAvault's own state.

## CPU while idle

Not a table, because a number here would be meaningless without a CPU-time
measurement over a window:

**Structurally, the daemon does nothing when idle.** Its three threads each block
in the OS:

- *main* — `GetMessage` on the tray, blocked until a menu event.
- *pipe* — `ConnectNamedPipe`, blocked until a client connects; then a blocking
  read until a line arrives.
- *deadline* — parked on a `Condvar` until a clipboard clear is due. With no copy
  pending the predicate is false and the wait is indefinite, so this thread is
  not woken at all.

There is no polling loop, no timer thread, no periodic vault scan, and no
auto-lock timer. Auto-lock is a pure function of the last-activity timestamp,
evaluated when the daemon already has a reason to wake — which means it fires at
the *next event* rather than exactly on time. For a vault that is harmless:
nothing can be read between two events, and an idle vault costs nothing to keep
locked.

The one timer in the product is a one-second `setInterval` in the **UI**, counting
down the auto-lock timer for display. It reads a number the daemon computed and
decides nothing.

## A bug this benchmark found

Worth recording, because it is the argument for checking a benchmark's own output.

The first run reported `unlock round trip: 19 ms`. Argon2id at 19 MiB cannot
possibly be that fast on this CPU. Two things were wrong:

1. The benchmark ignored the result of the request it was timing. `teavault-bench.exe`
   is not `teavault-app.exe`, so the tier check correctly refused its `init` — and
   the "19 ms" was the round-trip time of a *refusal*.
2. Behind that: **`init` required an unlocked vault, so `teavault init` could never
   have worked at all.** A fresh vault is by definition locked.

Both are fixed: the benchmark now prints whether the operation succeeded and
warns that the figure is meaningless if it did not, and `Operation::Init` is
exempt from the locked check. There is a regression test
(`creating_a_vault_is_possible_while_locked`).

A benchmark that swallows its own failure produces a confident number about
nothing. That is the specific failure mode this file is built to avoid.