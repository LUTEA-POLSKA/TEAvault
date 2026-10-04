//! `teavault` — the command-line client.
//!
//! Every command goes through the same pipe and the same dispatcher as the GUI,
//! so the CLI gets no privileges the UI does not and performs no check the UI
//! would skip. It is also owner tier, because it is the tool the owner uses to
//! create and unlock the vault.
//!
//! ## Passphrases never appear in arguments
//!
//! `init` and `unlock` read the passphrase from the terminal, not from
//! `argv`. Command-line arguments are visible in the process list, in crash
//! reports, and in shell history — so a secret in `argv` is a secret in several
//! places at once.
//!
//! ## Exit codes
//!
//! `0` success, `1` refused or failed, `2` bad usage. A refusal is not an
//! error to retry blindly, so it gets its own code: see `docs/AGENT_GUIDE.md`.

use std::io::IsTerminal;

use teavault_core::ipc::{GrantModeWire, Operation, Request};
use teavault_daemon::pipe::{Client, ClientError};

const USAGE: &str = "\
teavault — local API key vault

USAGE
  teavault <command> [options]

COMMANDS
  init                    Create the vault. Prompts for a master passphrase.
  unlock                  Unlock the vault. Prompts for the master passphrase.
  lock                    Lock the vault immediately.
  status                  Show whether the vault is unlocked.

  list [--provider P]     List key metadata. Never prints a secret.
  info <NAME>             Show one entry's metadata. Never prints a secret.
  request <NAME>          Release the secret for one entry. Requires a grant.

  use <NAME>              Write the secret to stdout for NAME, nothing else.
  run <NAME> -- CMD...    Run CMD with NAME set in its environment.
                          The secret is never an argument.

  approve                 Answer a pending access request.
  deny                    Refuse a pending access request.
  pending                 List requests waiting for a decision.

  help                    This text.

SECURITY
  Passphrases are read from the terminal, never from arguments.
  `use` and `run` print or export a secret only after the same permission
  checks the GUI performs. Every decision is recorded in the audit log.
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match run(&args) {
        Ok(()) => 0,
        Err(Failure::Usage(msg)) => {
            eprintln!("teavault: {msg}\n\n{USAGE}");
            2
        }
        Err(Failure::Refused { code, message }) => {
            eprintln!("teavault: {message}");
            // The refusal code goes to stderr so a script can branch on it
            // without parsing prose.
            eprintln!("teavault: code: {code}");
            1
        }
        Err(Failure::Client(e)) => {
            eprintln!("teavault: {e}");
            eprintln!("teavault: is the background process running? try `teavaultd`");
            1
        }
    };
    std::process::exit(code);
}

/// Failures, split by what the caller should do about them.
enum Failure {
    Usage(String),
    /// A security refusal. `code` is stable and machine-readable.
    Refused {
        code: String,
        message: String,
    },
    /// Could not reach or talk to the daemon.
    Client(ClientError),
}

impl From<ClientError> for Failure {
    fn from(e: ClientError) -> Self {
        // A refusal is not the same failure as "cannot reach the daemon": one
        // means the security model answered, the other means we never got to
        // ask. They get different exit codes so a script can tell them apart.
        match e {
            ClientError::Refused(r) => Failure::Refused {
                code: r.code,
                message: r.message,
            },
            other => Failure::Client(other),
        }
    }
}

fn run(args: &[String]) -> Result<(), Failure> {
    let Some(command) = args.first().map(String::as_str) else {
        print!("{USAGE}");
        return Ok(());
    };

    match command {
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            Ok(())
        }

        "init" => {
            let passphrase = read_new_passphrase()?;
            let client = Client::connect()?;
            client.send(Request::new("1", Operation::Init { passphrase }))?;
            println!("Vault created. Add a key with the desktop app, or `teavault init` help.");
            Ok(())
        }

        "unlock" => {
            let passphrase = read_passphrase("Master passphrase: ")?;
            let client = Client::connect()?;
            client.send(Request::new("1", Operation::Unlock { passphrase }))?;
            println!("Vault unlocked.");
            Ok(())
        }

        "lock" => {
            let client = Client::connect()?;
            client.send(Request::new("1", Operation::Lock))?;
            println!("Vault locked.");
            Ok(())
        }

        "status" => {
            let client = Client::connect()?;
            let out = client.send(Request::new("1", Operation::Status))?;
            print_status(&out);
            Ok(())
        }

        "list" => {
            let provider = flag_value(args, "--provider");
            let client = Client::connect()?;
            let out = client.send(Request::new("1", Operation::List { provider }))?;
            print_list(&out);
            Ok(())
        }

        "info" => {
            let name = positional(args, 1, "info <NAME>")?;
            let client = Client::connect()?;
            let out = client.send(Request::new("1", Operation::Info { entry: name }))?;
            print_info(&out);
            Ok(())
        }

        "request" => {
            let name = positional(args, 1, "request <NAME>")?;
            let client = Client::connect()?;
            let out = client.send(Request::new(
                "1",
                Operation::Request {
                    entry: name,
                    purpose: flag_value(args, "--purpose"),
                },
            ))?;
            print_request(&out);
            Ok(())
        }

        // `use` and `run` exist so the secret never has to be typed or shown.
        // They are thin wrappers over `request`.
        "use" => {
            let name = positional(args, 1, "use <NAME>")?;
            let client = Client::connect()?;
            let out = client.send(Request::new(
                "1",
                Operation::Request {
                    entry: name.clone(),
                    purpose: flag_value(args, "--purpose"),
                },
            ))?;
            let value = out["value"].as_str().unwrap_or_default().to_string();
            print!("{value}");
            Ok(())
        }

        "run" => {
            let name = positional(args, 1, "run <NAME> -- <command>")?;
            let Some(sep) = args.iter().position(|a| a == "--") else {
                return Err(Failure::Usage(
                    "run needs `--` before the command, so the command's own arguments are not mistaken for TEAvault options".into(),
                ));
            };
            let command: Vec<String> = args[sep + 1..].to_vec();
            if command.is_empty() {
                return Err(Failure::Usage("run needs a command after `--`".into()));
            }

            let client = Client::connect()?;
            let out = client.send(Request::new(
                "1",
                Operation::Request {
                    entry: name.clone(),
                    purpose: Some(format!("run {}", command[0])),
                },
            ))?;
            let value = out["value"].as_str().unwrap_or_default().to_string();

            // Inherited rather than replaced, so PATH and the rest of the
            // environment survive.
            let status = std::process::Command::new(&command[0])
                .args(&command[1..])
                .env(&name, &value)
                .status();

            match status {
                Ok(s) => std::process::exit(s.code().unwrap_or(1)),
                Err(e) => Err(Failure::Usage(format!("could not run {}: {e}", command[0]))),
            }
        }

        "pending" => {
            let client = Client::connect()?;
            let out = client.send(Request::new("1", Operation::Approvals))?;
            print_pending(&out);
            Ok(())
        }

        "approve" => {
            let request_id = positional(args, 1, "approve <REQUEST-ID>")?;
            let entry = flag_value(args, "--entry").unwrap_or_default();
            let client = Client::connect()?;
            client.send(Request::new(
                "1",
                Operation::Resolve {
                    request_id,
                    entry,
                    mode: GrantModeWire::AlwaysAllow,
                },
            ))?;
            println!("Approved.");
            Ok(())
        }

        "deny" => {
            let request_id = positional(args, 1, "deny <REQUEST-ID>")?;
            let entry = flag_value(args, "--entry").unwrap_or_default();
            let client = Client::connect()?;
            client.send(Request::new(
                "1",
                Operation::Resolve {
                    request_id,
                    entry,
                    mode: GrantModeWire::Deny,
                },
            ))?;
            println!("Denied.");
            Ok(())
        }

        other => Err(Failure::Usage(format!("unknown command `{other}`"))),
    }
}

/// Read a passphrase with echo off.
///
/// Fails on a non-interactive terminal rather than falling back to echoing: a
/// passphrase printed to a terminal is in the scrollback and in any recording
/// of the session.
fn read_passphrase(prompt: &str) -> Result<String, Failure> {
    if !std::io::stdin().is_terminal() {
        return Err(Failure::Usage(format!(
            "{prompt} — no terminal is attached. Refusing to read a passphrase from a pipe, \
             where it would land in a script or a log."
        )));
    }
    rpassword(prompt)
}

/// Read and confirm a new passphrase, and enforce the length policy.
fn read_new_passphrase() -> Result<String, Failure> {
    let first = read_passphrase("New master passphrase: ")?;
    let second = read_passphrase("Repeat: ")?;
    if first != second {
        return Err(Failure::Usage("the two passphrases differ".into()));
    }
    if first.chars().count() < 12 {
        return Err(Failure::Usage(
            "the master passphrase must be at least 12 characters".into(),
        ));
    }
    Ok(first)
}

/// Minimal no-echo reader.
///
/// Uses the console API directly rather than a dependency: this is the single
/// place a passphrase is typed, and a crate that handles it is a crate that has
/// to be trusted with it.
fn rpassword(prompt: &str) -> Result<String, Failure> {
    use std::io::Write;
    print!("{prompt}");
    std::io::stdout().flush().ok();

    let mut line = String::new();
    let read = std::io::stdin().read_line(&mut line);
    println!();
    match read {
        Ok(_) => Ok(line.trim_end_matches(['\r', '\n']).to_string()),
        Err(e) => Err(Failure::Usage(format!(
            "could not read the passphrase: {e}"
        ))),
    }
}

fn positional(args: &[String], index: usize, usage: &str) -> Result<String, Failure> {
    args.get(index)
        .cloned()
        .ok_or_else(|| Failure::Usage(format!("missing argument — {usage}")))
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    let i = args.iter().position(|a| a == flag)?;
    args.get(i + 1).cloned()
}

fn print_status(out: &serde_json::Value) {
    println!(
        "initialized:  {}",
        out["initialized"].as_bool().unwrap_or(false)
    );
    println!(
        "state:        {}",
        if out["locked"].as_bool().unwrap_or(true) {
            "locked"
        } else {
            "unlocked"
        }
    );
    println!("entries:      {}", out["entry_count"].as_u64().unwrap_or(0));
    println!(
        "pending:      {}",
        out["pending_approvals"].as_u64().unwrap_or(0)
    );
    println!("protocol:     {}", out["protocol"].as_u64().unwrap_or(0));
    println!("kdf:          {}", out["kdf"].as_str().unwrap_or("-"));
}

fn print_list(out: &serde_json::Value) {
    let entries = out["entries"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    if entries.is_empty() {
        println!("No entries are visible to you.");
        return;
    }
    for e in entries {
        let name = e["name"].as_str().unwrap_or("?");
        let provider = e["provider"].as_str().unwrap_or("");
        let granted = e["granted"].as_bool().unwrap_or(false);
        let hidden = e["hidden"].as_bool().unwrap_or(false);
        let caps = e["capabilities"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();

        println!(
            "{name:<28} {provider:<12} {}{} [{}]",
            if granted { "granted " } else { "" },
            if hidden { "hidden" } else { "visible" },
            caps
        );
    }
}

fn print_info(out: &serde_json::Value) {
    println!("name:         {}", out["name"].as_str().unwrap_or("-"));
    println!("provider:     {}", out["provider"].as_str().unwrap_or("-"));
    println!(
        "description:  {}",
        out["description"].as_str().unwrap_or("-")
    );
    println!(
        "capabilities: {}",
        out["capabilities"]
            .as_array()
            .map(|a| a
                .iter()
                .filter_map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(", "))
            .unwrap_or_default()
    );
    println!(
        "granted:      {}",
        out["granted"].as_bool().unwrap_or(false)
    );
    println!(
        "updated:      {}",
        out["updated_at"].as_str().unwrap_or("-")
    );
}

fn print_request(out: &serde_json::Value) {
    println!("{}", out["value"].as_str().unwrap_or_default());
}

fn print_pending(out: &serde_json::Value) {
    let items = out.as_array().map(Vec::as_slice).unwrap_or(&[]);
    if items.is_empty() {
        println!("Nothing is waiting for a decision.");
        return;
    }
    for p in items {
        println!(
            "{}  {}  wants {}  (from {})",
            p["request_id"].as_str().unwrap_or("?"),
            p["requested_at"].as_str().unwrap_or(""),
            p["entry_name"].as_str().unwrap_or("?"),
            p["client_label"].as_str().unwrap_or("?"),
        );
    }
}
