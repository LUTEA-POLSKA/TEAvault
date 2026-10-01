# Agent guide

Everything an AI agent or a program needs to use TEAvault. It is designed to be
read once and used without further questions.

## The one rule

**Discovering a key's name does not give you its value.** `list` and `info` are
metadata reads. `request` is a separate operation that requires a permission the
vault's owner granted. There is no third path, and no combination of `list` and
`info` adds up to a value.

## Transport

A Windows named pipe, `\\.\pipe\teavault-v1`. Line-delimited JSON, UTF-8. **One
request per connection.**

```text
→ {"v":1,"id":"1","op":"list"}
← {"v":1,"id":"1","ok":true,"result":{…}}
```

There is no HTTP server, no port and no TLS to configure. If you cannot open a
named pipe, there is no supported way in.

## Operations

### `list` — metadata for every key you may see

```json
{"v":1,"id":"1","op":"list"}
{"v":1,"id":"1","op":"list","provider":"OpenAI"}
```

```json
{
  "entries": [
    {
      "name": "OPENAI_API_KEY",
      "id": "9c1f…",
      "provider": "OpenAI",
      "available": true,
      "capabilities": ["llm", "embeddings"],
      "display_name": "OpenAI — production",
      "description": "primary model access",
      "granted": false,
      "hidden": false
    }
  ]
}
```

- `available` means **the vault is open**. It is not a claim that the key is
  valid; TEAvault never contacts a provider to find out.
- `provider` and `capabilities` are the owner's own labels. Metadata, not
  evidence.
- `granted` tells you whether `request` would be permitted right now.
- `hidden` entries are omitted unless you already hold a grant for them.

### `info` — one entry's metadata

```json
{"v":1,"id":"1","op":"info","entry":"OPENAI_API_KEY"}
```

Returns the same fields plus `created_at`, `updated_at`, and a `grants` array
containing **only your own** grants — so one client cannot enumerate who else has
access. Accepts either the entry id or the variable name.

### `request` — release the value

```json
{"v":1,"id":"1","op":"request","entry":"OPENAI_API_KEY"}
{"v":1,"id":"1","op":"request","entry":"OPENAI_API_KEY","purpose":"run the test suite"}
```

`purpose` is untrusted free text. It is shown, quoted and attributed, in the
owner's approval dialog. Nothing parses it.

On success:

```json
{"name":"OPENAI_API_KEY","value":"sk-…"}
```

On no grant:

```json
{
  "code": "needs_confirmation",
  "message": "this request needs the vault owner's approval",
  "request_id": "7b2e…",
  "retryable": true
}
```

The owner sees a dialog and answers it. If they allow, **you must ask again** —
the failed attempt created a pending request, it did not queue your value.

`status`, `lock`, `pending`, `approve` and `deny` also exist for a client running
in the user's own terminal. See `teavault --help`.

## Error codes

Branch on `code`, never on `message`.

| code | meaning | what to do |
|---|---|---|
| `locked` / `vault_locked` | the vault is locked | tell the user; there is no way around it |
| `needs_confirmation` | no grant; the owner was asked | ask again once they answer |
| `no_grant` | not permitted | do not retry; it will not change |
| `denied_by_user` | the owner refused | stop; retrying is ignoring a decision |
| `grant_expired` | the approval lapsed | ask the owner to re-approve |
| `invalid_passphrase` | wrong passphrase, or damaged keyring | do not retry blindly |
| `attempts_exhausted` | too many failed unlocks | stop; a `retry_after_secs` is given |
| `integrity` | data was modified or is damaged | **stop.** Never fall back to something weaker |
| `operation_not_allowed` | this client may not do that | do not retry |
| `not_found` | no such entry | check the name |
| `invalid` | malformed request | fix the request |
| `unsupported_format` | version mismatch | update your client |

`integrity` deserves emphasis: it is not a transient error. The right response is
to stop and tell the user, not to retry and not to look for a weaker path.

## From the command line

```sh
teavault list                                    # metadata, never values
teavault info OPENAI_API_KEY
teavault use OPENAI_API_KEY                      # the value on stdout, nothing else
teavault run OPENAI_API_KEY -- npx pytest         # value in the child's environment
```

`run` exists so the secret never has to be typed, echoed or copied. **Never put a
secret in a command-line argument** — it is visible in the process list, in crash
reports and in shell history.

`teavault` exits `0` on success, `1` on a refusal or failure, `2` on bad usage. A
refusal prints `teavault: code: <code>` to stderr.

## From Rust

```rust
use teavault_daemon::pipe::{Client, ClientError};
use teavault_core::ipc::{Operation, Request};

let client = Client::connect_with_retry(std::time::Duration::from_secs(2))?;

// 1. Discover. This can never return a secret value.
let list = client.send(Request::new("1", Operation::List { provider: None }))?;
let entries = list["entries"].as_array().cloned().unwrap_or_default();

// 2. Ask for one, specifically.
let out = match client.send(Request::new(
    "2",
    Operation::Request {
        entry: "OPENAI_API_KEY".into(),
        purpose: Some("run the test suite".into()),
    },
)) {
    Ok(v) => v,
    Err(ClientError::Refused(r)) => {
        // `needs_confirmation` means the owner was asked; they have not
        // answered yet. Do not retry in a loop.
        match r.code.as_str() {
            "needs_confirmation" => { /* wait for the user */ }
            "denied_by_user" => { /* stop */ }
            other => return Err(format!("refused: {other}").into()),
        }
        return Ok(());
    }
    Err(e) => return Err(e.to_string().into()),
};

let key = out["value"].as_str().ok_or("malformed response")?;
std::process::Command::new("npx")
    .arg("pytest")
    .env("OPENAI_API_KEY", key)
    .status()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Rules for a well-behaved client

1. **Ask for one key at a time**, and only when you need it.
2. **Prefer `allow once`.** A standing grant keeps working after you stop.
3. **Never log, print, cache or write the value** you receive. Not to a file, not
   to a log, not into your own context, not into a model prompt.
4. **Never ask for a key you were not given.** Requesting everything you can see
   is the exact pattern the permission model exists to make visible and refusable.
5. **Do not retry a refusal.** `denied_by_user` is a decision, not an obstacle.
6. **Do not attempt to work around a refusal.** There is no alternative path, and
   trying one is the behaviour the design is built to detect.
7. **Say where the value came from** in your output to the user, so a later reader
   can tell which operations touched the vault.