# Status

Honest state of the build, written so it can be checked against reality. If
anything here is wrong, that is a bug in this file.

Measured on Windows 11, i7-4790, release build.

## Test results

Everything below was **run**, not assumed.

```
cargo test --workspace
  teavault-core   lib    155 passed, 0 failed
  teavault-core   tests/boundary.rs   26 passed, 0 failed
  teavault-daemon lib      6 passed, 0 failed
  teavault-daemon tests/pipe_e2e.rs   8 passed, 0 failed
                                 195 total, 0 failed

cargo build --workspace                     clean, 0 warnings
cargo build --manifest-path src-tauri/...   clean, 0 warnings
cargo clippy --workspace --all-targets -D warnings   clean
npm --prefix ui run typecheck               clean
npm --prefix ui run build                   clean
cargo run --release -p teavault-daemon --bin teavault-bench   ran
.\scripts\verify-startup.ps1                               ran
```

The 8 `pipe_e2e` tests drive a **real Windows named pipe** with a real client, so
they cover `GetNamedPipeClientProcessId` identity resolution, the pipe's DACL,
the framing, and the tier that falls out of it.

`verify-startup.ps1` starts the staged binaries and asks Windows directly whether
the UI owns a visible window. That check exists because "the process is still
running" is not evidence a UI works — a Tauri app whose web view never
initialised also stays alive and prints nothing. It currently reports
`visible=True title='TEAvault'`.

**Test isolation:** `pipe_e2e` needs `\\.\pipe\teavault-v1` to itself. If a real
`teavaultd` is running, the suite fails — the panic message says so explicitly
rather than leaving a bare timeout.

## Done

| area | state |
|---|---|
| Key hierarchy | Argon2id → KEK → random data key → AES-256-GCM records |
| KDF hardening | parameters stored, re-validated on read, floor enforced, downgrade refused |
| Encrypted storage | atomic writes, fsync, file lock, index sealed separately from secrets |
| AAD binding | each secret bound to its entry id; replay across contexts fails |
| Lock / unlock | explicit lock, attempt counting, lockout that blocks the *correct* passphrase |
| Permissions | per client per key, allow-once / always / deny, deny beats allow, expiry, revocation |
| Discovery control | `list` and `info` cannot return a value, by type |
| Visibility | discoverable vs hidden, so the inventory is not disclosed by default |
| Audit log | hash-chained, DPAPI-bound, closed event enum, no secret-shaped field |
| Backup | encrypted only, integrity-checked before any write, merge-by-default |
| Local protocol | line-delimited JSON over a named pipe, 64 KiB cap, versioned |
| Pipe security | remote clients rejected, explicit SDDL DACL |
| Client identity | kernel-reported PID + image path; no client-supplied identity field exists |
| Owner tier | path-based; a copied binary elsewhere is refused |
| Daemon | event-driven, no polling, tray, clipboard clear-if-unchanged |
| CLI | `init unlock lock status list info request use run pending approve deny` |
| UI | React + TEAui only; main, detail, access, activity, settings screens |
| Idle | ~5.5 MiB working set idle; ~100 ms Argon2id unlock — see `BENCHMARKS.md` |

## Not done

Stated plainly rather than left to be discovered.

### Managed Access (the proxy) — not implemented

The design is in `ARCHITECTURE.md`. The protocol has **no operation for it**. It
is not claimed as working anywhere.

Before building it: endpoint allow-lists, SSRF prevention including redirects and
DNS rebinding, controlled headers and methods, size and time limits, rate limits,
and a guarantee that a key never reaches an error message, a log line or a
response body. That list is why it is a later phase.

### Not tested

- **No automated accessibility testing.** No axe run, no screen-reader pass. The
  UI uses TEAui's components so it inherits their semantics, but "inherits" is not
  "verified".
- **No UI integration tests.** The frontend is typechecked and builds; no test
  drives it. The screens have not been exercised against a live daemon in an
  automated run.
- **No cross-machine or multi-user testing.** Single user, single machine.
- **No upgrade or migration test.** There is no format migration path yet, so
  `UnsupportedFormat` is always a hard stop rather than something that upgrades.
- **The release build has not been code-signed.** That is why the owner tier is a
  path comparison rather than a signature check.
- **Windows 10 is not tested.** Only Windows 11 was used. Nothing in the code
  should require 11, but nothing proves it.
- **The tray icon is drawn by the shell**, using `IDI_APPLICATION`. A real `.ico`
  is generated at build time only because Tauri requires one.

### Known weaknesses

Fuller treatment in `THREAT_MODEL.md`; the sharpest ones:

1. **The owner tier is a path comparison.** Write access to the install directory
   is equivalent to being the owner. A copy of the binary *elsewhere* is refused;
   a replacement *at* the path is not.
2. **A granted agent can exfiltrate a key.** Nothing can help once a string is
   released. Managed Access is the only real answer and it is not built.
3. **Memory hygiene is best-effort.** A crash dump contains plaintext.
4. **The audit log is tamper-evident, not tamper-proof.**
5. **Passphrase entropy is not measured.** Length is enforced; entropy is not.
6. **The unlock passphrase crosses the web view's IPC boundary.** Deliberate;
   bounded; documented in `SECURITY.md` § 5.
7. **No dependency verification** — no vendoring, no reproducible builds.

## Not audited

TEAvault has had no external security review. The tests are thorough about the
properties they check and silent about everything else. Do not treat a passing
test run as evidence of correctness.

## Known rough edges

- `teavault init` and `unlock` require an interactive terminal and refuse to read a
  passphrase from a pipe. That is deliberate — a passphrase in a script is a
  passphrase in a log — but it means there is no non-interactive provisioning path.
- The daemon's `Shared` exposes the vault behind a `Mutex`, so requests serialise.
  Correct, and not a bottleneck at human request rates; it would be worth
  revisiting for a very large vault.
- Argon2id parameters are stored and re-validated, but nothing raises them over
  time. The keyring format already supports it; no re-wrapping driver exists yet.
- The UI's settings screen writes each card's changes separately, so a partial
  save across cards is possible. Each individual change is atomic.