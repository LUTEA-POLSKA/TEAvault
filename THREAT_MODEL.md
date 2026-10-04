# Threat model

Written so it can be argued with. If a claim here is wrong, that is a bug in the
design, and the file should change.

TEAvault stores API keys locally and releases them, one at a time, to programs the
user has approved.

---

## Assets

1. **API key values.** The thing worth stealing.
2. **The key inventory** — which providers you have keys for, how many, what
   they are for. Disclosed in the clear by most tools, and genuinely useful to an
   attacker choosing what to target.
3. **The approval graph** — which program may reach which key. Stealing this lets
   an attacker find the path of least resistance.
4. **The audit log** — evidence of what has already been accessed.

## Adversaries

### A1 — Offline reader

Has the vault files: a stolen laptop, a backup, a synced folder, a disk image.
No user present, no running process, no password.

**Defeated.** Files are AES-256-GCM under a data key wrapped by an
Argon2id-derived KEK. What they get is the KDF parameters and a ciphertext. The
only attack is guessing the passphrase, at 19 MiB and 2 passes per guess.
Metadata is encrypted too, so they learn nothing about the inventory either.

*Residual:* a weak passphrase. Length is enforced at creation (12 characters
minimum, configurable) but nobody measures entropy. A dictionary or a reused
password falls to an offline search.

### A2 — Local unprivileged process

Runs as the same Windows user. Can open the pipe, read files, spawn processes,
inspect the process list.

**Mostly defeated, with a stated gap.**

- Cannot reach the vault data: it is encrypted, and the key is only in a live
  unlocked session.
- Cannot reach vault *administration*: refused by the tier check before storage is
  touched, because its image path is not `teavault-app.exe`/`teavault.exe` next
  to the daemon.
- Cannot get a key value without either an existing grant (which it does not
  have) or the owner's approval in a dialog the user can read and refuse.

*Residual, and this is the honest part:*

- **A copy of the owner binary elsewhere on disk is refused** — that check works.
  **A replacement *at* the install path is not**, because TEAvault compares paths
  and is not signed. On a per-user install, write access to that directory is
  enough to obtain the owner tier.
- **An attacker who runs code as the user can wait.** When you approve a dialog,
  the attacker has the key. No local design prevents that. What it prevents is
  the attack being unattended: the request is visible, refusals are logged, and
  you can revoke.
- **An attacker who runs code as the user can read process memory in principle.**
  See `SECURITY.md` § 2 for exactly what zeroization does and does not achieve.

### A3 — Compromised agent / LLM prompt injection

An AI agent with legitimate tool access gets talked into requesting every key it
can find, or into exfiltrating one it was granted.

**Defeated for the un-granted case.** `list` returns names only, and it is a
separate operation from `request`. An agent that discovers `OPENAI_API_KEY` has
learned a *name*, not a value. Prompt injection cannot manufacture a grant: only
`request` creates an approval, and the owner answers it in a dialog showing which
program asked.

*Residual, and it is a design limit rather than a bug:*

- **Once a value is released, nothing can help.** If a granted key reaches an
  agent, that agent can copy, print or forward it. TEAvault cannot revoke a
  string. The only mitigation is granting as little as possible: `allow once`
  over `always allow`, hidden over discoverable.
- This is why **Managed Access exists as a future phase**: proxying the API call
  so the key never enters the agent's memory. It is not built. See
  `ARCHITECTURE.md`.

### A4 — Network attacker

Is on the network, or has DNS/ARP control.

**Out of scope by construction.** `PIPE_REJECT_REMOTE_CLIENTS` refuses remote
clients at the OS level. There is no listener, no port, no HTTP, no telemetry, no
update check. A machine that cannot be reached is not attackable over a network.

### A5 — Malicious or substituted dependency

A compromised crate in the build graph.

**Partially mitigated.** The dependency set is small and reviewed
(`ARCHITECTURE.md` § Dependencies); `teavault-core` is
`#![deny(unsafe_code)]`, which removes the largest class of supply-chain bug. But
a malicious `aes-gcm` would defeat everything, and nothing in the design detects
that. *Not mitigated:* reproducible builds, vendoring, or signature verification
of dependencies.

## What is explicitly out of scope

- **A physical attacker with an unlocked, running session.** Memory can be
  dumped; there is no defence in userspace.
- **A kernel-level or debugger-level attacker on the machine.** Nothing userspace
  survives that.
- **Another process running as an administrator.** It can read the vault files,
  and if the vault is unlocked it can read the process memory.
- **Social engineering.** A user who approves a dialog they should not have
  approved has handed over the key. The dialog is designed to make that harder —
  program, path, PID, elevation, target key, stated purpose, all visible — but it
  cannot make the user right.

## Design decisions and what they cost

| decision | bought | cost |
|---|---|---|
| metadata encrypted | inventory not disclosed to any local process | `list` requires an unlocked vault |
| random data key, not derived | passphrase change is O(32 bytes); no re-encryption window | one more secret to manage in memory |
| deny beats allow | revocation actually revokes | re-approving needs two operations |
| UI has no authority | a compromised frontend cannot widen access | one process hop on every action |
| path-based owner tier | accidental exposure impossible; a copied binary refused | **not** identity proof; see A2 |
| explicit locking only, no idle timeout | zero idle cost, no fuzzy deadline | an unlocked vault stays open until the user locks it |
| audit hash-chained | deletion and in-place edits detectable | **not** tamper-proof against a same-user attacker |
| DPAPI on the audit key only | account-bound log integrity | relies on DPAPI, which the same-user attacker can also call |
| 64 KiB request cap | bounds what a hostile client can make the daemon allocate | none in practice |

## Known weaknesses, ranked

1. **The owner tier is a path comparison, not identity.** Anything that can write
   to the install directory becomes the owner. Fixing this properly needs code
   signing plus an install layout the user cannot write. Not done.
2. **A same-user attacker survives approval.** Visible, loggable, revocable — but
   not preventable. This is inherent to a local tool.
3. **Managed Access is absent.** Agents that *are* granted a key can exfiltrate
   it. The proxy design is sketched; it is not implemented.
4. **Passphrase strength is not measured.** Length is enforced; entropy is not.
5. **The audit log is tamper-evident, not tamper-proof.**
6. **Memory hygiene is best-effort**, and a crash dump contains plaintext.
7. **The unlock passphrase crosses the web view's IPC boundary.** Accepted
   deliberately; see `SECURITY.md` § 5.
8. **No dependency verification** — no vendoring, no reproducible builds.

## What would raise the bar

- Code signing plus an install directory only an installer can write, replacing
  the path comparison with a real identity check.
- Managed Access, so a granted agent never holds a key at all.
- Argon2 parameter increases over time, with re-wrapping on first unlock — the
  keyring format already supports it; nothing drives it yet.
- A memory-safe verification of the release binaries by a second party.