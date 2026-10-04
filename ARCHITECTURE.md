# Architecture

## The one decision everything follows from

**The UI has no authority.** It cannot decrypt anything. It cannot skip a check.
It is a client of the same local pipe the CLI uses, subject to the same
permissions, and every decision is made in `teavault-core`.

The alternative — a UI that holds the vault so it can render instantly — is the
shape most desktop secret tools have, and it means every XSS, every compromised
dependency and every malicious npm postinstall in the frontend tree is a full key
compromise. Here it is an inconvenience: the attacker still has to satisfy the
grant check, which is the thing that was designed to be hard.

```
┌─────────────────┐   ┌──────────────────┐
│ teavault-app    │   │ teavault (CLI)   │
│ (Tauri + TEAui) │   │                  │
└────────┬────────┘   └────────┬─────────┘
         │                     │   both are just clients
         └──────────┬──────────┘
                    │  \\.\pipe\teavault-v1
                    │  line-delimited JSON, one request per connection
                    ▼
         ┌──────────────────────┐
         │ teavaultd            │  background process
         │  ├ pipe server       │  identity from GetNamedPipeClientProcessId
         │  ├ tray              │
         │  └ clipboard         │
         └──────────┬───────────┘
                    │  the only caller
                    ▼
         ┌──────────────────────┐
         │ teavault-core        │  THE security instance
         │  dispatcher          │  ← every authorisation decision
         │  policy / grants     │
         │  crypto / storage    │
         │  audit               │
         └──────────────────────┘
```

## Request path

Every request — from the UI, from the CLI, from any local process — takes the
same route through four checks, in this order:

1. **Envelope.** Protocol version and id. A future client must not be able to
   send a `request` that this build interprets more permissively.
2. **Tier.** May this client perform an operation of this tier at all? Checked
   from the kernel-reported image path, *before* any storage is touched, so an
   agent asking to create a key is refused without reading anything.
3. **Locked.** Anything needing the data key is refused. Five operations are
   exempt, and each is exempt for the same structural reason — the operation is
   either about the locked state itself, or about a vault that has nothing to
   unlock:

   | exempt | why |
   |---|---|
   | `lock` | working while locked is its entire purpose |
   | `status` | the user must be able to ask whether it is locked |
   | `unlock` | it *ends* the locked state; requiring an unlocked vault here would make unlocking impossible |
   | `init` | a fresh vault is by definition locked; requiring an unlocked vault would make creating one impossible |
   | `wipe` | it exists for a vault whose passphrase nobody has; requiring an unlocked vault would make it unreachable exactly when it is needed |

   The last three can only be exempt safely because each one is uninteresting to
   a lock: `unlock` can only *add* access and only with the correct passphrase;
   `init` and `wipe` have no data key to reach. `unlock` was **not** exempt in an
   earlier revision, which meant a created vault could never be opened again —
   see the exemption's own doc comment in `ipc/mod.rs` for why it is easy to get
   this wrong and why the fixture tests did not catch it.
4. **The operation's own rules.** The grant check for `request`, existence
   checks, validation.

An error at any step returns immediately. There is no partial success and no
best-effort continuation. See `crates/teavault-core/src/ipc/dispatch.rs`.

This is in the core, not the daemon, because authorisation is a security
decision and the spec is explicit that no caller may skip one. Putting it in the
core also means the security tests are ordinary unit tests — no pipe, no process,
no Windows API — which is the difference between tests that get run and tests that
get skipped.

## The three operations

| operation | needs a grant | can return a secret |
|---|---|---|
| `list` | no, but respects visibility | **no** — the type has no field for one |
| `info` | no, but respects visibility | **no** — same type |
| `request` | **yes** | yes, and only this one |

`list` and `info` return `ApiKeyMetadata`, which has no secret field. So "metadata
never leaks a key" is a property of the type rather than of a code path someone
has to remember.

## Storage layout

```jsonc
// vault.data
{
  "format_version": 1,
  "index":   { "nonce": "…", "ciphertext": "…" },   // sealed VaultIndex
  "secrets": [                                        // one sealed blob per entry
    { "entry_id": "…", "sealed": { "nonce": "…", "ciphertext": "…" } }
  ]
}
```

The index — entry metadata plus the whole grant set — is sealed as one blob.
That is a privacy decision: metadata in the clear would let any process learn
which providers you use. Each secret is a **separate** blob keyed to its entry id,
so listing entries decrypts no secret at all, and a ciphertext cannot be moved
between entries.

Writes go through `storage::atomic`: temp file in the same directory, `fsync`,
rename, under an exclusive lock on a separate `vault.lock`. A crash leaves either
the old complete file or the new one.

## Idle design

Low background consumption is a product feature here, not an optimisation. The
rules:

- **No polling.** Not in the daemon, not in the UI (with one display-only
  exception, below).
- **No permanent WebView.** The UI is a separate process; closing its window
  destroys the browser engine with it.
- **No timers.** The daemon's three threads each block in the OS:
  - *main* — `GetMessage` on the tray, blocked until a menu event.
  - *pipe* — `ConnectNamedPipe`, blocked until a client connects; then a blocking
    read until a line arrives.
  - *deadline* — parked on a `Condvar` until a clipboard clear is due. With no
    copy pending the predicate is false and the wait is indefinite.
- **No periodic vault scans.** The data file is read when a request needs it.
- **No auto-lock at all.** Locking is explicit — the tray, the UI button, or
  shutdown. An idle timeout was considered and dropped: it needs a wake-up to
  evaluate it, and every candidate wake-up (a timer, a poll, a per-request check)
  either costs idle work or makes the deadline fuzzy. "Lock when you are done" is
  a decision the user can actually make; a timeout they cannot predict is worse
  than none.
- **One exception, in the UI.** A one-second interval counts down the clipboard
  clear deadline for display. It reads a number the daemon computed and decides
  nothing; a missed tick costs a stale countdown.

Measured numbers, with conditions, are in [`BENCHMARKS.md`](BENCHMARKS.md).
They are measurements, not guarantees.

## Thread layout

| thread | why it exists |
|---|---|
| main | the tray message pump; `GetMessage` blocks and cannot also wait on a pipe |
| pipe | `ConnectNamedPipe` blocks; the tray must stay live while it waits |
| deadline | alive only between a clipboard copy and its clear deadline |

## Managed access (not built)

The intended design: an agent makes an API call *through* TEAvault, so the key
never enters the agent's memory at all.

```
agent ──(request, no secret)──▶ TEAvault ──▶ provider
```

This is **not implemented**, and the protocol has no operation for it. It is not
claimed as working anywhere in this repository. Before it can be built it needs a
security design and tests covering at least:

- an allow-list of provider endpoints per key, enforced before any connection;
- SSRF prevention — a key must never be usable against an address the user did
  not name, including redirects and DNS rebinding;
- controlled headers and methods, so the proxy cannot be turned into a general
  HTTP relay;
- request and response size limits, and timeouts;
- rate limits;
- and above all: the API key must never appear in an error message, a log line, or
  a response body.

That list is the reason it is a later phase rather than an extra endpoint.

## Dependencies

Chosen for being maintained, audited and boring:

| crate | why |
|---|---|
| `aes-gcm` 0.11 | RustCrypto; hardware-accelerated where available |
| `argon2` 0.6 | the reference Argon2 implementation, with the `blake2`/`ahash` stack the spec expects |
| `zeroize` 1.9 | the standard for wiping on drop |
| `sha2`, `hmac` 0.10/0.12 | RustCrypto |
| `windows` 0.62 | first-party bindings; the pipe and tray are thin wrappers over documented OS APIs |
| `serde`, `serde_json`, `thiserror`, `time`, `uuid`, `fs2`, `getrandom` | unremarkable and well-known |
| `tauri` 2 | the app shell; a system WebView rather than a bundled Chromium |
| `@tea-ui/*` | the mandated UI kit |

No network client, no async runtime, no logging framework, no `unsafe` in the
core. The dependency count is small on purpose: in a program whose job is to hold
secrets, every dependency is a thing to audit.

`radix-ui` and `tailwind-merge` appear in `ui/package-lock.json` as
**transitive dependencies of TEAui itself**, declared in `@tea-ui/admin`'s
manifest. TEAvault adds no component library of its own.