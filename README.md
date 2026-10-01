# TEAvault

A native Windows application for storing API keys encrypted on disk and handing
them to tools deliberately, one key at a time, with your approval in the loop.

TEAvault is **only** for API keys and API credentials. It is not a general
password manager, and it is not a secrets manager for your whole infrastructure.

The idea in one paragraph: an AI agent (or any program) can ask *what keys do I
have* and get names, providers and capabilities — but getting an actual key
value is a separate operation that requires a permission you granted, and an
unrecognised program gets nothing at all without asking you first.

---

## Status

This is an early, working build. What that means concretely is in
[`STATUS.md`](STATUS.md) — read it before trusting it with anything real. In
short: the security core, the local protocol, the permissions model, the CLI and
the audit log are implemented and tested; the UI is implemented and builds; the
managed proxy mode is *not* built.

---

## What it does

- **Encrypted at rest.** Keys are sealed with AES-256-GCM under a random data
  key, which is itself sealed with a key derived from your master passphrase by
  Argon2id. Your passphrase is never stored, never logged, and never in a
  command-line argument.
- **Three operations, not one.** `list` and `info` return metadata and *cannot*
  return a key value — the return types have no field for one. `request` releases
  a value, and only after a permission check.
- **Per-key, per-program permissions.** An approval covers one program and one
  key. It can be one-shot, standing with an expiry, or a refusal. All are
  revocable, and a refusal beats an earlier approval.
- **You see what is being asked for.** When an unknown program asks for a key,
  TEAvault shows you the program, its path, its PID, whether it is elevated, and
  which key it wants. The dialog cannot show the key's value.
- **Honest about limits.** Memory hygiene, clipboard clearing and log integrity
  are all partial. See [`SECURITY.md`](SECURITY.md) for exactly where each one
  stops.

## What it does not do

- It does not manage infrastructure secrets, passwords, or certificates.
- It does not validate keys against providers. Sending a key to check it would
  send your secret somewhere it does not control, so provider and capability
  labels are your own description and nothing more.
- It does not recover a forgotten passphrase. There is no backdoor and no
  master recovery key. **There is no recovery if you lose the passphrase.**
- It does not have a managed proxy mode yet. See
  [`ARCHITECTURE.md`](ARCHITECTURE.md#managed-access-not-built).

---

## Install

You need Windows 10 or 11 and the [Rust toolchain](https://rustup.rs/) plus
[Node.js 20+](https://nodejs.org/).

```sh
git clone https://github.com/landnevermore/TEAvault
cd TEAvault
.\scripts\build-local.ps1 -Release
```

That builds everything and stages the three binaries into `dist/`.

Then, in this order:

```sh
# 1. the background process — leave it running
.\dist\teavaultd.exe

# 2. create the vault, in an interactive terminal
.\dist\teavault init

# 3. the UI
.\dist\teavault-app.exe
```

Day to day you will not start the UI by hand: the tray icon opens it, locks the
vault, and quits it.

**They must stay in one directory.** `teavaultd` grants the owner tier only to
`teavault-app.exe` and `teavault.exe` *in its own directory*, so running the UI
from somewhere else leaves it agent tier, where it can do nothing. The script
exists to make that mistake impossible.

To check the whole path works:

```sh
.\scripts\verify-startup.ps1
```

It starts the staged binaries against a scratch vault and reports four things:
that the binaries share a directory, that the UI serves the **embedded**
frontend rather than a dev server, that Windows created a visible window, and
that the CLI reaches the daemon.

> **If the window says "localhost refused the connection"**, the app was built
> without `--features custom-protocol`. `cargo build` alone does not enable it —
> only `tauri build` does — so the binary embeds `devUrl` (`localhost:5173`)
> instead of the frontend, and the window fails to load with nothing in the
> console to explain it. Rebuild with `.\scripts\build-local.ps1`, which passes the
> feature. `verify-startup.ps1` detects exactly this and says so.

The CLI needs an interactive terminal for `init` and `unlock`: it refuses to
read a passphrase from a pipe, where it would land in a script or a log.

`teavault --help` lists everything.

### For AI agents

`docs/AGENT_GUIDE.md` is the short version — three operations, the JSON shapes,
the error codes, and a Rust client example. Once the daemon is running:

```sh
teavault list                              # metadata, never values
teavault run OPENAI_API_KEY -- npx some-tool   # value in the child's environment
```

---

## How it is put together

```
crates/teavault-core/     the security instance. crypto, storage, permissions,
                          audit, and the request dispatcher. Nothing else has
                          authority.
crates/teavault-daemon/   teavaultd: named pipe server, tray, clipboard.
crates/teavault-cli/      teavault.
src-tauri/                the UI shell. Forwards to the daemon, decides nothing.
ui/                       React + TEAui.
```

The UI has no privileged access to the vault. It is a client of the same pipe the
CLI uses, subject to the same checks. That is the central structural decision:
if the web view is compromised, the attacker still has to satisfy the grant
check.

Read [`ARCHITECTURE.md`](ARCHITECTURE.md) for why, and
[`THREAT_MODEL.md`](THREAT_MODEL.md) for what that does and does not defend
against.

## Documentation

| file | what is in it |
|---|---|
| [`SECURITY.md`](SECURITY.md) | crypto choices, what each one protects, and where it stops |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | components, the request path, the idle design |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | adversaries, their capabilities, and the residual risks |
| [`docs/AGENT_GUIDE.md`](docs/AGENT_GUIDE.md) | the local protocol, for programs and agents |
| [`docs/UI_NOTES.md`](docs/UI_NOTES.md) | which TEAui components are used, and the one gap |
| [`BENCHMARKS.md`](BENCHMARKS.md) | measured idle cost, with the conditions |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | how to work on it |
| [`STATUS.md`](STATUS.md) | what is done, what is not, what is untested |

## Tests

```sh
cargo test --workspace              # 195 tests
cd src-tauri && cargo test
npm --prefix ui run typecheck       # the frontend, against TEAui's real types
```

The security tests are ordinary unit tests — the dispatcher runs without a pipe
or a Windows API, so they can actually be run and read. A separate integration
suite drives a real named pipe with a real client to cover identity resolution
and the pipe's access control. That suite needs the pipe to itself: quit any
running `teavaultd` first, or its panic message will tell you so.

## Licence

MIT OR Apache-2.0.

TEAvault is not audited. Do not treat it as reviewed.