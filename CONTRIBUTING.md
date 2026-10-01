# Contributing

TEAvault holds API keys. That changes what "careful" means here: a change that
looks harmless can remove a check, and the tests that would notice it are the ones
you are most likely to skip.

Read [`SECURITY.md`](SECURITY.md) and [`THREAT_MODEL.md`](THREAT_MODEL.md) before
your first change. Not because you will forget the details, but because they are
full of statements like "and this is where it stops", and those are the parts a
refactor breaks.

## Ground rules

1. **The core is the only security instance.** If your change needs a permission
   check, a crypto operation or a decision about whether a secret may be released,
   it belongs in `teavault-core`. Not in the daemon, not in the CLI, not in the UI,
   not in `src-tauri`.
2. **No check moves into a caller.** A function that returns a secret must be
   reachable only from a path that has already asked the permission question.
   Prefer making that structurally true — a type with no field for a secret is
   better than a function that remembers to strip one.
3. **No new `unsafe` in `teavault-core`.** It is `#![deny(unsafe_code)]`. If you
   genuinely need it, that is a signal the code belongs elsewhere.
4. **No secret in an error, a log, a test failure message, or a `Debug` impl.**
   `SecretBytes` and `SecretString` have hand-written `Debug` for this reason.
   Keep it that way.
5. **No new dependency without a reason in the PR description.** In a program whose
   job is holding secrets, every dependency is something to audit. Check the
   licence, the maintenance status and the advisories.
6. **A refusal is an answer.** Never catch an error and retry it, fall back to a
   default, or return something weaker. `integrity` is not a transient fault.
7. **Do not claim a security property the code does not have.** If you cannot
   enforce it, document the limit in `THREAT_MODEL.md`. An honest "this is the
   weakest point" is worth more than a confident sentence that is wrong.

## Setup

```sh
.\scripts\build-local.ps1              # debug; add -Release for a release build
npm --prefix ui install                # if you want to work on the frontend only
```

The script stages all three binaries into `dist/`, which is required for a
working run: the owner tier is a path comparison against the daemon's own
directory, so the UI and the CLI have to sit next to it.

To check the whole path — including whether Windows really created a UI window:

```sh
.\scripts\verify-startup.ps1
```

It uses a scratch vault and cleans up after itself.

### Two Tauri traps, both silent

**`cargo build` does not embed the frontend.** Only `tauri build` passes
`--features custom-protocol`. Without it the binary embeds `build.devUrl`
(`localhost:5173`), the window opens on "localhost refused the connection", and
nothing is written to stderr — the process looks healthy.
`build-local.ps1` passes the feature; `verify-startup.ps1` detects the failure by
occupying port 5173 and seeing whether the UI reaches for it. Do not "simplify"
the build command back to a plain `cargo build`.

**`cargo test`/`cargo check` do not need the frontend**, because `dev` mode never
reads `frontendDist`. That is intentional, so a Rust-only change does not require
`npm install`.

For frontend development, run the two halves separately — the Rust side in dev
mode, the Vite server serving 5173:

```sh
npm --prefix ui run dev                  # terminal 1
cargo run --manifest-path src-tauri/Cargo.toml   # terminal 2
```

## Before opening a PR

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm --prefix ui run typecheck
npm --prefix ui run build
cargo build --manifest-path src-tauri/Cargo.toml
```

All of it must be clean. A skipped test is a failure unless the PR says why, in
the description, explicitly.

**Quit any running `teavaultd` before `cargo test`.** The pipe name is global, so
the `pipe_e2e` suite needs it to itself. The panic message says this if you
forget.

## Writing tests here

Security tests should be **ordinary unit tests**. The dispatcher lives in
`teavault-core` precisely so the authorisation logic can be tested without a pipe,
a process or a Windows API. If you find yourself needing a named pipe to test a
permission decision, the decision is in the wrong place — move it.

Assert the *refusal*, not just the success. The interesting cases are:

- a wrong passphrase, and that it is **indistinguishable** from a damaged file;
- a downgraded KDF parameter in a tampered keyring;
- a ciphertext moved to a different entry;
- a revoked, expired or denied grant;
- a client that has a grant for one key asking for another;
- a hidden entry that must not appear in `list`;
- a `list` or `info` response containing no secret-shaped field.

When you add an operation, add it to the tier tests. The tier check is the thing
that stops an arbitrary local process from reaching vault administration, and it
is enforced by a test that every owner operation is owner-tier.

## The TEAui rule

TEAui is the only UI library. If TEAui lacks something you need, document the gap
in `docs/UI_NOTES.md` and compose what it does export.

**Do not add a second component library. Do not modify the TEAui repository. Do
not copy components out of it.**

Verify the API exists before using it:

```sh
cd ui && cat node_modules/@tea-ui/core/dist/index.d.ts
```

`npm run typecheck` will catch an invented prop, and it caught several during
development — `direction="row"` where TEAui wants `"horizontal"`, `variant=` on
`Alert` where it wants `tone=`. Guessing is not faster.

## Performance

The daemon is expected to be idle. Before adding anything that runs on a timer:

- **Can it run when the daemon already wakes up for another reason?** Auto-lock
  works this way — it is a pure function evaluated on the next event rather than a
  tick. That is why an idle vault costs nothing to keep locked.
- **Can it be a one-shot instead of a repeating one?** The clipboard deadline is a
  `Condvar` with an indefinite wait, not a poll.
- **What does it cost when idle?** If you added it, measure it with
  `cargo run --release -p teavault-daemon --bin teavault-bench` and put the number
  in `BENCHMARKS.md`.

## Documentation is part of the change

A change that alters a security property updates `SECURITY.md` and
`THREAT_MODEL.md` in the same commit. A new operation goes in
`docs/AGENT_GUIDE.md` with its error codes. A change that closes a gap in
`STATUS.md` says so there.

Stale documentation is worse than none, because it is trusted.

## Commit messages

Explain the reasoning, especially where a choice looks odd:

```text
Fix: deny must beat an earlier standing grant

Revocation that leaves an old approval in place is not revocation, so
GrantSet::decide checks deny first regardless of insertion order.

Without this, a user who denied a program kept a working permission to
every key that program had ever been approved for.
```

Not: "fix grant precedence".

## Reporting a vulnerability

Open a GitHub issue marked as a security concern, or email the maintainer. Please
give the concrete path — client, operation, what was refused and what you expected
— rather than "the permissions are broken". The audit log is the first thing to
look at and it will usually answer the question.