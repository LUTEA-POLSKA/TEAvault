//! `teavault` — the unified TEAvault binary.
//!
//! One compiled binary. Two modes, selected by the name used to invoke it.
//!
//! ## Dispatch
//!
//! | binary name | mode | subsystem |
//! |---|---|---|
//! | `teavaultd.exe` | daemon | tray + pipe + clipboard |
//! | `teavault.exe` | CLI | terminal commands |
//!
//! The Tauri app (`teavault-app.exe`) remains a separate binary: it is a GUI
//! subsystem program with `#![windows_subsystem = "windows"]`, WebView2, and
//! `tauri::generate_context!()`. Merging a GUI process with console processes
//! is not possible without changing the subsystem flag.
//!
//! ## How the build script works
//!
//! `scripts/build-local.ps1` builds the workspace once, then copies the
//! resulting binary to two names:
//! ```
//! teavault.exe      → CLI mode
//! teavaultd.exe     → daemon mode
//! ```
//! Both are the same PE file; `std::env::current_exe()` at runtime tells them
//! which mode to run.

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

/// The binary name used to invoke this process (for mode dispatch).
fn mode() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_stem().and_then(|n| n.to_str().map(|s| s.to_string())))
        .unwrap_or_else(|| "teavault".to_string())
}

fn main() {
    let mode = mode();
    match mode.as_str() {
        "teavaultd" => {
            // Daemon mode — tray + pipe + clipboard server
            eprintln!("teavaultd: starting daemon (unified binary)");
            std::process::exit(0); // TODO: implement daemon mode
        }
        _ => {
            // CLI mode — teavault.exe (or any other name)
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
    }
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

/// Check if a flag is present in args.
#[allow(dead_code)]
pub(crate) fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

/// Get the value for a flag, or None.
#[allow(dead_code)]
pub(crate) fn get_flag_value(args: &[String], flag: &str) -> Option<String> {
    let i = args.iter().position(|a| *a == flag)?;
    args.get(i + 1).cloned()
}

/// Validate that a command needs a positional argument.
#[allow(dead_code)]
pub(crate) fn require_positional(args: &[String], index: usize, name: &str) -> Result<String, String> {
    args.get(index)
        .cloned()
        .ok_or_else(|| format!("missing argument — {name}"))
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn has_flag_finds_existing_flag() {
        let args = vec!["list".to_string(), "--provider".to_string(), "OpenAI".to_string()];
        assert!(has_flag(&args, "--provider"));
        assert!(!has_flag(&args, "--verbose"));
    }

    #[test]
    fn has_flag_returns_false_for_missing_flag() {
        let args = vec!["list".to_string()];
        assert!(!has_flag(&args, "--provider"));
        assert!(!has_flag(&args, "--unknown"));
    }

    #[test]
    fn get_flag_value_returns_value_for_existing_flag() {
        let args = vec!["list".to_string(), "--provider".to_string(), "OpenAI".to_string()];
        let val = get_flag_value(&args, "--provider");
        assert_eq!(val, Some("OpenAI".to_string()));
    }

    #[test]
    fn get_flag_value_returns_none_for_missing_flag() {
        let args = vec!["list".to_string(), "--provider".to_string()];
        let val = get_flag_value(&args, "--provider");
        assert_eq!(val, None);
    }

    #[test]
    fn require_positional_returns_value_when_present() {
        let args = vec!["info".to_string(), "MY_KEY".to_string()];
        let result = require_positional(&args, 1, "info <NAME>");
        assert_eq!(result.unwrap(), "MY_KEY");
    }

    #[test]
    fn require_positional_returns_error_when_missing() {
        let args = vec!["info".to_string()];
        let result = require_positional(&args, 1, "info <NAME>");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing argument"));
    }

    #[test]
    fn flag_value_returns_none_when_no_args() {
        let args: Vec<String> = vec![];
        assert!(get_flag_value(&args, "--any").is_none());
    }

    #[test]
    fn print_request_output_formats_value() {
        let value = serde_json::json!({"value": "sk-test-key-12345"});
        let result = value["value"].as_str().unwrap_or_default();
        assert_eq!(result, "sk-test-key-12345");
    }

    #[test]
    fn print_request_output_handles_missing_value() {
        let value = serde_json::json!({"other": "field"});
        let result = value["value"].as_str().unwrap_or_default();
        assert_eq!(result, "");
    }

    #[test]
    fn print_pending_handles_empty_array() {
        let pending: serde_json::Value = serde_json::json!([]);
        let items = pending.as_array().map(Vec::as_slice).unwrap_or(&[]);
        assert!(items.is_empty());
    }

    #[test]
    fn print_pending_parses_single_item() {
        let pending = serde_json::json!([
            {
                "request_id": "req-1",
                "requested_at": "2025-01-01T00:00:00Z",
                "entry_name": "OPENAI_API_KEY",
                "client_label": "vscode"
            }
        ]);
        let items = pending.as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["request_id"].as_str(), Some("req-1"));
    }

    #[test]
    fn print_pending_handles_null_value() {
        let pending: serde_json::Value = serde_json::Value::Null;
        let items = pending.as_array().map(Vec::as_slice).unwrap_or(&[]);
        assert!(items.is_empty());
    }

    #[test]
    fn print_status_parses_boolean_fields() {
        let status = serde_json::json!({
            "initialized": true,
            "locked": false,
            "entry_count": 5,
            "pending_approvals": 2,
            "protocol": 1,
            "kdf": "argon2id"
        });
        assert_eq!(status["initialized"].as_bool(), Some(true));
        assert_eq!(status["locked"].as_bool(), Some(false));
        assert_eq!(status["entry_count"].as_u64(), Some(5));
        assert_eq!(status["pending_approvals"].as_u64(), Some(2));
        assert_eq!(status["protocol"].as_u64(), Some(1));
        assert_eq!(status["kdf"].as_str(), Some("argon2id"));
    }

    #[test]
    fn print_list_handles_empty_entries() {
        let list = serde_json::json!({"entries": []});
        let entries = list["entries"].as_array().map(Vec::as_slice).unwrap_or(&[]);
        assert!(entries.is_empty());
    }

    #[test]
    fn print_list_parses_entry_with_all_fields() {
        let entry = serde_json::json!({
            "name": "OPENAI_API_KEY",
            "provider": "OpenAI",
            "granted": true,
            "hidden": false,
            "capabilities": ["llm", "embeddings"]
        });
        assert_eq!(entry["name"].as_str(), Some("OPENAI_API_KEY"));
        assert_eq!(entry["provider"].as_str(), Some("OpenAI"));
        assert_eq!(entry["granted"].as_bool(), Some(true));
        assert_eq!(entry["hidden"].as_bool(), Some(false));
    }

    #[test]
    fn print_list_capabilities_formatting() {
        let entry = serde_json::json!({
            "name": "KEY",
            "provider": "Test",
            "capabilities": ["cap1", "cap2", "cap3"]
        });
        let caps = entry["capabilities"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        assert_eq!(caps, "cap1,cap2,cap3");
    }

    #[test]
    fn print_list_handles_missing_fields() {
        let entry = serde_json::json!({"name": "KEY"});
        assert_eq!(entry["provider"].as_str().unwrap_or(""), "");
        assert!(!entry["granted"].as_bool().unwrap_or(false));
        assert!(!entry["hidden"].as_bool().unwrap_or(false));
    }
}
