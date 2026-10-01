# Security

What TEAvault protects, how, and — more importantly — where each protection
stops. Every "limitations" section below is real and load-bearing.

TEAvault has **not** been independently audited. Nothing here should be read as
a claim that it has been.

---

## 1. Cryptography

No algorithm in TEAvault is TEAvault's own. Everything is an upstream primitive:

| purpose | primitive | notes |
|---|---|---|
| passphrase → key | Argon2id, v1.3 | OWASP parameters: m=19 MiB, t=2, p=1 |
| record encryption | AES-256-GCM | 96-bit random nonce per operation, 128-bit tag |
| audit chain | SHA-256 | links each entry to the previous |
| audit integrity | HMAC-SHA-256 | bound to the Windows account via DPAPI |

### Argon2id parameters

Defaults are m=19456 KiB (19 MiB), t=2, p=1, output 32 bytes — the values the
OWASP Password Storage Cheat Sheet recommends, and also `argon2::Params::DEFAULT`,
so there is no TEAvault-specific tuning to remember. They are stored in the
keyring and re-validated on every read.

`KdfParams::validate` enforces a floor of 8 MiB and a ceiling of 4 GiB. This
matters: **the keyring is untrusted input at exactly the moment it matters most.**
Someone who can edit `vault.keyring` would otherwise set `m_cost_kib: 8` and turn
a 19 MiB derivation into a microsecond one. That check is the difference between
a passphrase being expensive to guess and being free. There is a test for it.

### Key hierarchy

```
master passphrase ──Argon2id──▶ KEK ──AES-256-GCM──▶ data key ──AES-256-GCM──▶ records
   (never stored)              (derived)             (random, 32 bytes)
```

The data key is **random, not derived**. Two consequences:

- Changing the passphrase re-wraps 32 bytes instead of re-encrypting every entry.
  There is no window in which a crash loses keys.
- Records are protected by a key with no algebraic relationship to your
  passphrase beyond the wrap, so an offline attacker who guesses a passphrase
  still has to get the unwrap exactly right.

The data key exists only inside an unlocked session and is wiped when it ends.

### Nonces

Random 96-bit nonces, generated from the OS CSPRNG. GCM's catastrophic failure
is nonce reuse under one key, so the bound is stated rather than waved at: a
random 96-bit nonce keeps collision probability below 2⁻³² across ~4 billion
operations under a single key, far beyond any realistic vault lifetime. The data
key is regenerated on every passphrase change, resetting the per-key budget.

### Associated data

Every seal authenticates a context string, not just the bytes:

- keyring: `"teavault:v1:keyring:data-key"`
- index: `"teavault:v1:vault:index"`
- each secret: `"teavault:v1:vault:secret:<entry id>"`

So a vault record cannot be replayed as a keyring, and one entry's ciphertext
cannot be moved to another entry. There is a test that does exactly the move and
asserts it fails.

### What is on disk

| file | contents |
|---|---|
| `vault.keyring` | KDF parameters, salt, wrapped data key — all public or ciphertext |
| `vault.data` | sealed index (metadata + grants) and per-entry sealed secrets |
| `audit.keyring` | DPAPI-wrapped audit chain key |
| `audit.log` | hash-chained events, no secrets |
| `settings.json` | preferences — the only plaintext file, and it has no secret field |

**Metadata is encrypted.** A deliberate choice with a cost: if metadata were in
the clear so a locked vault could answer `list`, every process on the machine
would learn which providers you have keys for. The inventory is itself
sensitive, so `list` requires an unlocked vault. What `list` returns once
unlocked still never contains a key value.

### Recovery

There is none, by design. Losing the passphrase loses the data key. No backdoor,
no universal key, no escrow. This is stated before the vault is created, not
discovered afterwards.

Backups are sealed with a key derived from a **separate** passphrase you choose
at export time, so a leaked backup file is not a leaked vault.

---

## 2. Memory hygiene

`teavault-core` is `#![deny(unsafe_code)]` and every secret buffer is a
`zeroize`-backed container that is overwritten on drop rather than merely
dropped. `SecretBytes` and `SecretString` deliberately do not derive `Debug`; the
manual impl prints the length only.

### Limitations — read this part

Zeroization in Rust is a **reduction in exposure window, not a guarantee**:

- **The allocator may have copied it.** A `Vec` that reallocates leaves the old
  buffer in freed heap memory.
- **The OS may have paged or swapped it.** TEAvault cannot lock pages or disable
  the crash dump.
- **A crash dump will contain it.** Nothing in this design prevents a dump
  including process memory.
- **Argon2's internal block state** is freed by the library, which does not
  promise to wipe it.
- **`String` conversions happen.** A secret becomes an owned `String` at the
  moment it is handed to a caller, wrapped in `Zeroizing` so it wipes too — but
  that copy existed.

So: a determined attacker with physical access and a memory-dump capability may
recover a key from an unlocked session. TEAvault reduces the time the plaintext
is reachable and stops the easy cases. It does not stop the hard one, and no
userspace design does.

---

## 3. Local access control

Three layers, outermost first:

1. **`PIPE_REJECT_REMOTE_CLIENTS`.** A client on another machine cannot connect.
   TEAvault is not a network service and does not become one by accident.
2. **An explicit DACL** built from SDDL, granting the local system account and
   built-in users. Built rather than inherited, because named pipe default
   security descriptors are frequently more permissive than people assume.
3. **Per-operation tier checks** in the dispatcher, keyed on the image path the
   kernel reports.

### Client identity

`GetNamedPipeClientProcessId` returns the PID of the process on the other end.
That is a kernel answer. The image path is then read from that process handle
with `PROCESS_QUERY_LIMITED_INFORMATION`. **Nothing in the request body
participates** — the protocol has no field for a client to name itself, and a
test asserts that adding one would fail.

A client fingerprint is `filename|image path`, lower-cased. The PID is
deliberately *not* part of it: approving `node.exe` from one project should not
require re-approving the next `node.exe`, and a PID alone would let any process
claim to be a previously-approved one.

### The owner tier — the weakest point, stated plainly

Vault administration (create/edit/delete, grants, settings, passphrase) is
reachable only by a client whose image path is `teavault-app.exe` **or**
`teavault.exe` in the same directory the daemon was launched from.

That is a path comparison. It means:

- A copy of the UI binary in `%TEMP%` is **refused**. That is the attack it
  actually stops, and accidental exposure is impossible.
- Anyone who can write to the install directory can replace that binary and
  obtain the owner tier. On a per-user install, that is a real risk.
- TEAvault does not verify Authenticode, because it is not signed and claiming
  otherwise would be theatre.

### Residual risk: same-user processes

An attacker who already runs code as you can read process memory in principle,
can wait for you to approve a dialog, and can copy files off disk. TEAvault
cannot prevent that. What it does prevent is the attack being **silent and
unattended**: every refusal and every approval is in the audit log, and no
program gets a value without a decision you made.

See [`THREAT_MODEL.md`](THREAT_MODEL.md) for the full picture.

---

## 4. Permissions

A grant names exactly one client, exactly one entry, one access mode, optionally
one project directory, and optionally an expiry.

Precedence, and the order matters:

1. **Deny** beats everything, including an older standing approval.
2. **Expired** is reported as expired, not as absent — so you can tell why an
   approval stopped working.
3. Otherwise a usable grant permits.
4. A spent one-shot grant is treated as absent. That is what "allow once" means.

A one-shot grant is spent **after** the secret was successfully produced, so a
failed decrypt does not burn your approval.

Grants live inside the encrypted index, so someone who copies the data files
learns neither who has access nor how to add themselves.

### `list` and `info` cannot leak a value

Not by policy — by type. `ApiKeyMetadata` has no secret field, so serialising
one cannot produce one. A test asserts the serialised form contains no
secret-shaped key. If someone later adds a `secret: Option<String>` to that
struct, several tests fail.

### Discoverability

Each entry is either **discoverable** (listed to any local client) or **hidden**
(not listed until someone holds a grant for it). Discoverable means the *name*
is public; the *value* still needs an approval. Hidden protects the inventory.

---

## 5. The web view

The UI is a separate process that talks to the daemon over the local pipe. It
holds no authority: it cannot decrypt anything, and it has no code path that
bypasses a check.

Its capabilities are limited to invoking this crate's own commands
(`src-tauri/capabilities/default.json`): no filesystem, no shell, no HTTP, no
asset protocol. The CSP forbids remote origins.

**Where the passphrase is exposed:** the unlock and backup-passphrase fields
cross the web view's IPC boundary into Rust. That is a real exposure — a
compromised frontend could read them — and it is accepted because the passphrase
has to be typed somewhere and the alternative (having the daemon show its own
unlock dialog, with no CLI unlock at all) is worse for the product. The exposure
is bounded: the process is owner-tier by path, and the value is used once and
never stored.

---

## 6. Clipboard

- The clipboard is **only cleared if it still holds what TEAvault put there.**
  A password you copied from another program in the meantime is never
  overwritten. `MemoryClipboard::externally_set` exists to test exactly this.
- Copying returns the **masked** form to the caller, so the UI never receives
  the value it just copied.
- Copying a key requires a grant, exactly like a pipe request. Clipboard readers
  are not a smaller risk than pipe readers.

**What clearing cannot do:** un-copy a secret. Any program can already have read
it, Windows clipboard history may have recorded it, and a screen-share tool may
have captured it. The clipboard is a channel to the whole session. The UI says
so, next to the button.

---

## 7. Audit log

Hash-chained: each entry carries the SHA-256 of the previous entry plus its own
payload, and — when a chain key is available — an HMAC over it. The chain key is
random and wrapped with Windows DPAPI.

**Why DPAPI, and why not on the data key.** Wrapping the *data key* with DPAPI
would hand it to every process running as the user and destroy the passphrase
barrier entirely. So DPAPI wraps only the audit chain key, which protects nothing
confidential. It buys account-binding of the log's integrity without weakening
anything else.

### Limitations

This is **tamper-evidence, not tamper-proofing.** An attacker with full control of
the user account can also call DPAPI, rewrite the whole file, and recompute the
chain. What it does catch is casual truncation, accidental deletion, and offline
editing with a text editor. It gives an investigator a chain they can verify.

What is never written: key values, passphrases, derived keys, `Authorization`
headers, request bodies. `AuditKind` is a closed enum with no free-form map, so
there is nowhere to put one — a test asserts the serialised events contain no
secret-shaped field.

---

## 8. Failure policy

- Every error is a **refusal**, not a hiccup. There is no `Err` variant from
  which a caller recovers by falling back to plaintext or retrying with weaker
  parameters.
- A failed decryption never falls back. `Error::Integrity` has no recovery path.
- The distinction between a wrong passphrase and a damaged keyring is
  deliberately erased: telling them apart tells an offline attacker which they
  are looking at, and there is no different action for you either way.
- Failed unlock attempts are counted; five in a row triggers a lockout that
  **also blocks the correct passphrase**, because a lockout that does not would
  not slow an attacker who knows the passphrase but wants to time their attempts.
- A corrupt import is refused before anything is written, so a failed restore
  cannot leave a half-merged vault.