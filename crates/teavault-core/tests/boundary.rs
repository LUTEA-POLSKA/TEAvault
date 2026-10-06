//! Integration tests for the request boundary.
//!
//! These exercise the exact paths an agent, the CLI and the UI take, with no
//! pipe and no Windows API — because [`Dispatcher`] is where authorisation
//! lives, and a security test that needs a named pipe to run is a security test
//! nobody runs.

use std::path::PathBuf;

use teavault_core::{
    ipc::{dispatch::Caller, Operation, OwnerCheck, Request, Tier},
    model::{ClientIdentity, GrantMode},
    paths::VaultPaths,
    Vault,
};

const PASS: &[u8] = b"a test passphrase of decent length";

/// A vault in a temp directory, unlocked, with two entries.
fn fixture() -> (tempfile::TempDir, Vault, OwnerCheck) {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = Vault::open(VaultPaths::new(dir.path())).unwrap();
    vault.create(PASS).unwrap();

    vault
        .create_entry(
            "OPENAI_API_KEY",
            "OpenAI",
            "OpenAI",
            Some("primary model access".into()),
            vec!["llm".into(), "embeddings".into()],
            teavault_core::model::Visibility::Discoverable,
            teavault_core::crypto::SecretString::new(b"sk-openai-value-0001".to_vec()),
            None,
        )
        .unwrap();

    vault
        .create_entry(
            "INTERNAL_ONLY",
            "Internal",
            "Acme",
            None,
            vec!["internal".into()],
            teavault_core::model::Visibility::Hidden,
            teavault_core::crypto::SecretString::new(b"internal-secret-0002".to_vec()),
            None,
        )
        .unwrap();

    let owner = OwnerCheck::from_exe_path(
        PathBuf::from(r"C:\Program Files\TEAvault\teavaultd.exe").as_path(),
        "teavault-app.exe",
    );
    (dir, vault, owner)
}

fn agent(name: &str) -> Caller {
    Caller::agent(ClientIdentity::new(4242, format!(r"C:\tools\{name}")))
}

fn owner() -> Caller {
    Caller::owner(ClientIdentity::new(
        1,
        r"C:\Program Files\TEAvault\teavault-app.exe",
    ))
}

#[test]
fn a_category_roundtrips_through_create_update_and_list() {
    let (_dir, mut vault, _oc) = fixture();

    let created = vault
        .create_entry(
            "CATEGORY_TOUR_KEY",
            "Category",
            "OpenAI",
            None,
            vec!["llm".into()],
            teavault_core::model::Visibility::Discoverable,
            teavault_core::crypto::SecretString::new(b"sk-x".to_vec()),
            Some("llm".into()),
        )
        .unwrap();
    assert_eq!(created.category.as_deref(), Some("llm"));

    let moved = vault
        .update_entry(
            &created.id,
            "OpenAI",
            "OpenAI",
            None,
            vec!["llm".into()],
            teavault_core::model::Visibility::Discoverable,
            Some("ci".into()),
        )
        .unwrap();
    assert_eq!(moved.category.as_deref(), Some("ci"));

    // Moving back to Uncategorized clears the field rather than leaving "".
    let cleared = vault
        .update_entry(
            &created.id,
            "OpenAI",
            "OpenAI",
            None,
            vec!["llm".into()],
            teavault_core::model::Visibility::Discoverable,
            None,
        )
        .unwrap();
    assert_eq!(cleared.category, None);
}

#[test]
fn list_carries_the_category_but_never_the_secret() {
    let (dir, mut vault, owner_check) = fixture();

    // Seed one categorised entry and one without.
    let _ = vault
        .create_entry(
            "CI_DEPLOY_KEY",
            "Deploy",
            "GitHub",
            None,
            vec!["ci".into()],
            teavault_core::model::Visibility::Discoverable,
            teavault_core::crypto::SecretString::new(b"sk-ci".to_vec()),
            Some("ci".into()),
        )
        .unwrap();
    let _ = vault
        .create_entry(
            "MISC_KEY",
            "Misc",
            "Other",
            None,
            vec![],
            teavault_core::model::Visibility::Discoverable,
            teavault_core::crypto::SecretString::new(b"sk-misc".to_vec()),
            None,
        )
        .unwrap();

    let listed = call(
        &mut vault,
        &owner_check,
        &owner(),
        Operation::List { provider: None },
    );
    let entries = listed
        .get("entries")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap();
    let by_name = |name: &str| {
        entries
            .iter()
            .find(|e| e.get("name").and_then(|n| n.as_str()) == Some(name))
            .unwrap()
            .clone()
    };

    assert_eq!(
        by_name("CI_DEPLOY_KEY")
            .get("category")
            .and_then(|c| c.as_str()),
        Some("ci")
    );
    assert_eq!(by_name("MISC_KEY").get("category"), None);
    for e in &entries {
        let json = e.to_string();
        assert!(!json.contains("sk-"), "list must not leak a secret");
    }

    let _ = dir;
}

fn call(
    vault: &mut Vault,
    owner_check: &OwnerCheck,
    caller: &Caller,
    op: Operation,
) -> serde_json::Value {
    let mut d = teavault_core::ipc::dispatch::Dispatcher::new(vault, owner_check);
    let req = Request::new("t1", op);
    let resp = d.handle(caller, &req);
    assert!(
        resp.is_ok(),
        "expected success, got {:?}",
        resp.error.map(|e| (e.code, e.message))
    );
    resp.result.expect("checked")
}

fn call_err(
    vault: &mut Vault,
    owner_check: &OwnerCheck,
    caller: &Caller,
    op: Operation,
) -> teavault_core::ipc::ErrorBody {
    let mut d = teavault_core::ipc::dispatch::Dispatcher::new(vault, owner_check);
    let resp = d.handle(caller, &Request::new("t1", op));
    assert!(!resp.is_ok(), "expected a refusal, got a result");
    resp.error.expect("checked")
}

// ------------------------------------------------------------ the core claim

#[test]
fn list_never_returns_a_secret_even_when_unlocked() {
    let (_d, mut v, oc) = fixture();
    let out = call(
        &mut v,
        &oc,
        &agent("agent.exe"),
        Operation::List { provider: None },
    );
    let text = out.to_string();
    assert!(!text.contains("sk-openai-value-0001"));
    assert!(!text.contains("internal-secret-0002"));
    // It does return the names, which is the entire point of discovery.
    assert!(text.contains("OPENAI_API_KEY"));
}

#[test]
fn info_never_returns_a_secret_even_when_unlocked() {
    let (_d, mut v, oc) = fixture();
    let out = call(
        &mut v,
        &oc,
        &agent("agent.exe"),
        Operation::Info {
            entry: "OPENAI_API_KEY".into(),
        },
    );
    let text = out.to_string();
    assert!(!text.contains("sk-openai-value-0001"));
    assert!(text.contains("primary model access"));
}

#[test]
fn request_without_a_grant_is_refused_and_asks_for_approval() {
    let (_d, mut v, oc) = fixture();
    let e = call_err(
        &mut v,
        &oc,
        &agent("agent.exe"),
        Operation::Request {
            entry: "OPENAI_API_KEY".into(),
            purpose: Some("run tests".into()),
        },
    );
    assert_eq!(e.code, "needs_confirmation");
    assert!(e.request_id.is_some(), "the UI needs a handle to answer");
    assert!(!e.message.contains("sk-"), "the refusal leaked a key");
}

#[test]
fn the_secret_is_not_in_the_audit_log_after_a_refusal() {
    let (_d, mut v, oc) = fixture();
    let _ = call_err(
        &mut v,
        &oc,
        &agent("agent.exe"),
        Operation::Request {
            entry: "OPENAI_API_KEY".into(),
            purpose: None,
        },
    );
    let log = serde_json::to_string(v.audit().events()).unwrap();
    assert!(!log.contains("sk-openai-value-0001"));
    assert!(!log.contains("internal-secret-0002"));
    assert!(log.contains("approval_requested"));
}

#[test]
fn an_approved_request_returns_the_key_to_that_client_only() {
    let (_d, mut v, oc) = fixture();
    let caller = agent("agent.exe");

    // Ask, get a pending approval.
    let err = call_err(
        &mut v,
        &oc,
        &caller,
        Operation::Request {
            entry: "OPENAI_API_KEY".into(),
            purpose: None,
        },
    );
    let request_id = err.request_id.unwrap();

    // A different client cannot answer someone else's approval.
    let bad = call_err(
        &mut v,
        &oc,
        &agent("other.exe"),
        Operation::Resolve {
            request_id: request_id.clone(),
            entry: "OPENAI_API_KEY".into(),
            mode: teavault_core::ipc::GrantModeWire::AlwaysAllow,
        },
    );
    assert_eq!(bad.code, "operation_not_allowed");

    // The owner resolves it.
    call(
        &mut v,
        &oc,
        &owner(),
        Operation::Resolve {
            request_id,
            entry: "OPENAI_API_KEY".into(),
            mode: teavault_core::ipc::GrantModeWire::AlwaysAllow,
        },
    );

    let out = call(
        &mut v,
        &oc,
        &caller,
        Operation::Request {
            entry: "OPENAI_API_KEY".into(),
            purpose: None,
        },
    );
    assert_eq!(out["value"], "sk-openai-value-0001");
}

#[test]
fn a_granted_client_cannot_use_the_same_grant_for_another_key() {
    let (_d, mut v, oc) = fixture();
    let caller = agent("agent.exe");
    let id = v.resolve_entry_id("OPENAI_API_KEY").unwrap();
    v.create_grant(
        &caller.identity,
        &id,
        GrantMode::AlwaysAllow { expires_at: None },
    )
    .unwrap();

    // Granted for one key, asked for a different one.
    let e = call_err(
        &mut v,
        &oc,
        &caller,
        Operation::Request {
            entry: "INTERNAL_ONLY".into(),
            purpose: None,
        },
    );
    assert_eq!(e.code, "needs_confirmation");
}

#[test]
fn an_unknown_client_gets_nothing_at_all() {
    let (_d, mut v, oc) = fixture();
    let stranger = agent("stranger.exe");

    // It cannot create keys.
    assert_eq!(
        call_err(
            &mut v,
            &oc,
            &stranger,
            Operation::Create {
                name: "NEW_KEY".into(),
                display_name: "New".into(),
                provider: "OpenAI".into(),
                description: None,
                capabilities: vec![],
                hidden: false,
                secret: "value".into(),
                category: None,
            }
        )
        .code,
        "operation_not_allowed"
    );

    // It cannot grant itself access.
    assert_eq!(
        call_err(
            &mut v,
            &oc,
            &stranger,
            Operation::Grant {
                entry: "OPENAI_API_KEY".into(),
                client_fingerprint: "stranger.exe|attacker".into(),
                client_label: "attacker".into(),
                mode: teavault_core::ipc::GrantModeWire::AlwaysAllow,
                expires_at: None,
            }
        )
        .code,
        "operation_not_allowed"
    );

    // It cannot see the access list.
    assert_eq!(
        call_err(&mut v, &oc, &stranger, Operation::Access).code,
        "operation_not_allowed"
    );

    // It cannot read the audit log.
    assert_eq!(
        call_err(&mut v, &oc, &stranger, Operation::Audit { limit: 10 }).code,
        "operation_not_allowed"
    );
}

#[test]
fn a_hidden_entry_is_invisible_to_an_ungranted_client() {
    let (_d, mut v, oc) = fixture();
    let out = call(
        &mut v,
        &oc,
        &agent("agent.exe"),
        Operation::List { provider: None },
    );
    let text = out.to_string();
    assert!(
        !text.contains("INTERNAL_ONLY"),
        "a hidden entry leaked into list"
    );

    // And `info` refuses rather than confirming it exists.
    let e = call_err(
        &mut v,
        &oc,
        &agent("agent.exe"),
        Operation::Info {
            entry: "INTERNAL_ONLY".into(),
        },
    );
    assert_eq!(e.code, "no_grant");
}

#[test]
fn a_hidden_entry_appears_once_a_grant_exists() {
    let (_d, mut v, oc) = fixture();
    let caller = agent("agent.exe");
    let id = v.resolve_entry_id("INTERNAL_ONLY").unwrap();
    v.create_grant(
        &caller.identity,
        &id,
        GrantMode::AlwaysAllow { expires_at: None },
    )
    .unwrap();

    let out = call(&mut v, &oc, &caller, Operation::List { provider: None });
    assert!(out.to_string().contains("INTERNAL_ONLY"));
}

#[test]
fn revoking_a_grant_stops_further_releases() {
    let (_d, mut v, oc) = fixture();
    let caller = agent("agent.exe");
    let id = v.resolve_entry_id("OPENAI_API_KEY").unwrap();
    let grant_id = v
        .create_grant(
            &caller.identity,
            &id,
            GrantMode::AlwaysAllow { expires_at: None },
        )
        .unwrap();

    call(
        &mut v,
        &oc,
        &caller,
        Operation::Request {
            entry: "OPENAI_API_KEY".into(),
            purpose: None,
        },
    );

    v.revoke_grant(&grant_id).unwrap();

    let e = call_err(
        &mut v,
        &oc,
        &caller,
        Operation::Request {
            entry: "OPENAI_API_KEY".into(),
            purpose: None,
        },
    );
    assert_eq!(
        e.code, "needs_confirmation",
        "a revoked grant must stop working"
    );
}

#[test]
fn a_deny_beats_an_existing_approval() {
    let (_d, mut v, oc) = fixture();
    let caller = agent("agent.exe");
    let id = v.resolve_entry_id("OPENAI_API_KEY").unwrap();
    v.create_grant(
        &caller.identity,
        &id,
        GrantMode::AlwaysAllow { expires_at: None },
    )
    .unwrap();

    call(
        &mut v,
        &oc,
        &owner(),
        Operation::Grant {
            entry: "OPENAI_API_KEY".into(),
            client_fingerprint: caller.identity.fingerprint(),
            client_label: "agent.exe".into(),
            mode: teavault_core::ipc::GrantModeWire::Deny,
            expires_at: None,
        },
    );

    let e = call_err(
        &mut v,
        &oc,
        &caller,
        Operation::Request {
            entry: "OPENAI_API_KEY".into(),
            purpose: None,
        },
    );
    assert_eq!(e.code, "denied_by_user");
}

#[test]
fn an_expired_grant_does_not_work() {
    let (_d, mut v, oc) = fixture();
    let caller = agent("agent.exe");
    let id = v.resolve_entry_id("OPENAI_API_KEY").unwrap();
    v.create_grant(
        &caller.identity,
        &id,
        GrantMode::AlwaysAllow {
            expires_at: Some(teavault_core::model::now_unix() - 1),
        },
    )
    .unwrap();

    let e = call_err(
        &mut v,
        &oc,
        &caller,
        Operation::Request {
            entry: "OPENAI_API_KEY".into(),
            purpose: None,
        },
    );
    assert_eq!(e.code, "grant_expired");
}

#[test]
fn allow_once_permits_exactly_one_release() {
    let (_d, mut v, oc) = fixture();
    let caller = agent("agent.exe");
    let id = v.resolve_entry_id("OPENAI_API_KEY").unwrap();
    v.create_grant(&caller.identity, &id, GrantMode::AllowOnce)
        .unwrap();

    let first = call(
        &mut v,
        &oc,
        &caller,
        Operation::Request {
            entry: "OPENAI_API_KEY".into(),
            purpose: None,
        },
    );
    assert_eq!(first["value"], "sk-openai-value-0001");

    let second = call_err(
        &mut v,
        &oc,
        &caller,
        Operation::Request {
            entry: "OPENAI_API_KEY".into(),
            purpose: None,
        },
    );
    assert_eq!(second.code, "needs_confirmation");
}

// -------------------------------------------------------------- lock / tier

#[test]
fn nothing_but_lock_and_status_works_while_locked() {
    let (_d, mut v, oc) = fixture();
    v.lock().unwrap();

    let caller = agent("agent.exe");

    // Agent-tier operations are refused because the vault is locked.
    for op in [
        Operation::List { provider: None },
        Operation::Info {
            entry: "OPENAI_API_KEY".into(),
        },
        Operation::Request {
            entry: "OPENAI_API_KEY".into(),
            purpose: None,
        },
    ] {
        let e = call_err(&mut v, &oc, &caller, op);
        assert_eq!(
            e.code, "vault_locked",
            "{} should be refused while locked",
            e.code
        );
    }

    // Owner-tier operations are refused by the *tier* check first, which runs
    // before storage is touched — so the code differs, and correctly so.
    for op in [Operation::Access, Operation::Audit { limit: 5 }] {
        let e = call_err(&mut v, &oc, &caller, op);
        assert_eq!(e.code, "operation_not_allowed");
    }

    // And the owner is refused for the real reason.
    let e = call_err(&mut v, &oc, &owner(), Operation::Access);
    assert_eq!(e.code, "vault_locked");

    // Lock and status still work — that is the point of exempting them.
    assert!(call(&mut v, &oc, &caller, Operation::Status)["locked"]
        .as_bool()
        .unwrap());
    call(&mut v, &oc, &caller, Operation::Lock);
}

#[test]
fn a_grant_cannot_be_used_while_locked_but_survives_the_lock() {
    let (_d, mut v, oc) = fixture();
    let caller = agent("agent.exe");
    let id = v.resolve_entry_id("OPENAI_API_KEY").unwrap();
    v.create_grant(
        &caller.identity,
        &id,
        GrantMode::AlwaysAllow { expires_at: None },
    )
    .unwrap();

    // While locked, nothing is released regardless of the grant.
    v.lock().unwrap();
    let e = call_err(
        &mut v,
        &oc,
        &caller,
        Operation::Request {
            entry: "OPENAI_API_KEY".into(),
            purpose: None,
        },
    );
    assert_eq!(e.code, "vault_locked");
    assert!(!e.message.contains("sk-"));

    // After unlocking, the still-valid grant works again. Grants are
    // deliberately persistent rather than session-scoped: re-prompting on every
    // unlock would train users to click through the dialog without reading it.
    v.unlock(PASS).unwrap();
    let out = call(
        &mut v,
        &oc,
        &caller,
        Operation::Request {
            entry: "OPENAI_API_KEY".into(),
            purpose: None,
        },
    );
    assert_eq!(out["value"], "sk-openai-value-0001");
}

#[test]
fn a_restart_comes_up_locked() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut v = Vault::open(VaultPaths::new(dir.path())).unwrap();
        v.create(PASS).unwrap();
        v.create_entry(
            "K",
            "K",
            "OpenAI",
            None,
            vec![],
            teavault_core::model::Visibility::Discoverable,
            teavault_core::crypto::SecretString::new(b"value".to_vec()),
            None,
        )
        .unwrap();
        assert!(v.is_unlocked());
    }

    // A brand-new process, same files.
    let v2 = Vault::open(VaultPaths::new(dir.path())).unwrap();
    assert!(!v2.is_unlocked(), "a restart must not come up unlocked");
    assert_eq!(
        v2.entry_count().unwrap(),
        0,
        "no entry count should be readable while locked"
    );
}

#[test]
fn an_owner_tier_claim_is_not_accepted_without_the_right_binary() {
    let (_d, mut v, oc) = fixture();

    // Mirror exactly what the daemon does: derive the tier from the image path
    // the kernel reports, then build the caller. A binary that merely calls
    // itself `teavault-app.exe` from elsewhere is agent tier.
    let identity = ClientIdentity::new(9, r"C:\Users\Someone\Downloads\teavault-app.exe");
    let tier = {
        let d = teavault_core::ipc::dispatch::Dispatcher::new(&mut v, &oc);
        d.tier_for(&identity)
    };

    let impostor = Caller { identity, tier };
    assert_eq!(tier, Tier::Agent);

    let e = call_err(
        &mut v,
        &oc,
        &impostor,
        Operation::Delete {
            entry: "OPENAI_API_KEY".into(),
        },
    );
    assert_eq!(e.code, "operation_not_allowed");
    assert!(
        v.resolve_entry_id("OPENAI_API_KEY").is_ok(),
        "the entry must survive the refused delete"
    );
}

#[test]
fn the_tier_is_recomputed_from_the_image_path_not_the_claim() {
    let (_d, mut v, oc) = fixture();
    let d = teavault_core::ipc::dispatch::Dispatcher::new(&mut v, &oc);
    let right = ClientIdentity::new(1, r"C:\Program Files\TEAvault\teavault-app.exe");
    let wrong = ClientIdentity::new(1, r"C:\elsewhere\teavault-app.exe");

    assert_eq!(d.tier_for(&right), Tier::Owner);
    assert_eq!(d.tier_for(&wrong), Tier::Agent);
}

// ------------------------------------------------------------- malformed

#[test]
fn a_malformed_line_is_refused_without_panicking() {
    let (_d, mut v, oc) = fixture();
    let caller = agent("agent.exe");
    {
        let mut d = teavault_core::ipc::dispatch::Dispatcher::new(&mut v, &oc);
        for line in ["", "not json", "{}", "[]", "null", "{\"v\":1}"] {
            let resp = d.handle_line(&caller, line);
            assert!(!resp.is_ok(), "{line:?} should be refused");
        }
    }
}

#[test]
fn an_oversized_request_is_refused() {
    // The framing layer enforces this, but the envelope should also refuse a
    // pathological id rather than allocating for it.
    let (_d, mut v, oc) = fixture();
    let resp = {
        let mut d = teavault_core::ipc::dispatch::Dispatcher::new(&mut v, &oc);
        let req = Request::new("x".repeat(10_000), Operation::Status);
        d.handle(&agent("agent.exe"), &req)
    };
    assert!(!resp.is_ok());
}

#[test]
fn a_protocol_version_mismatch_is_refused() {
    let (_d, mut v, oc) = fixture();
    let mut req = Request::new("1", Operation::Status);
    req.v = 99;
    let resp = {
        let mut d = teavault_core::ipc::dispatch::Dispatcher::new(&mut v, &oc);
        d.handle(&agent("agent.exe"), &req)
    };
    assert_eq!(resp.error.unwrap().code, "unsupported_format");
}

#[test]
fn a_client_declared_name_is_never_used_as_its_identity() {
    // There is no field in the protocol for a client to name itself. This test
    // pins that: adding such a field later would be the change that breaks the
    // model, and this is what makes that visible.
    //
    // No vault is needed — this is a property of the serialised request alone,
    // which is the point: identity never reaches the wire at all.
    let json = serde_json::to_string(&Request::new(
        "1",
        Operation::Request {
            entry: "OPENAI_API_KEY".into(),
            purpose: None,
        },
    ))
    .unwrap();
    for forbidden in ["client", "pid", "path", "identity", "process"] {
        assert!(
            !json.contains(forbidden),
            "the protocol carries a {forbidden} field, which a client could set"
        );
    }
}

// ------------------------------------------------------------------ backup

#[test]
fn a_backup_export_contains_no_plaintext() {
    let (dir, mut v, oc) = fixture();
    let target = dir.path().join("out.teavault");
    let out = call(
        &mut v,
        &oc,
        &owner(),
        Operation::BackupExport {
            path: target.display().to_string(),
            passphrase: "backup-pass".into(),
        },
    );
    assert!(out["path"].as_str().unwrap().ends_with("out.teavault"));

    let bytes = std::fs::read(&target).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("sk-openai-value-0001"));
    assert!(!text.contains("OPENAI_API_KEY"));
}

#[test]
fn an_agent_cannot_export_a_backup() {
    let (_d, mut v, oc) = fixture();
    let e = call_err(
        &mut v,
        &oc,
        &agent("agent.exe"),
        Operation::BackupExport {
            path: "C:\\tmp\\x.teavault".into(),
            passphrase: "p".into(),
        },
    );
    assert_eq!(e.code, "operation_not_allowed");
}

// -------------------------------------------------------------- audit log

#[test]
fn the_audit_log_records_the_release_without_the_value() {
    let (_d, mut v, oc) = fixture();
    let caller = agent("agent.exe");
    let id = v.resolve_entry_id("OPENAI_API_KEY").unwrap();
    v.create_grant(
        &caller.identity,
        &id,
        GrantMode::AlwaysAllow { expires_at: None },
    )
    .unwrap();
    call(
        &mut v,
        &oc,
        &caller,
        Operation::Request {
            entry: "OPENAI_API_KEY".into(),
            purpose: None,
        },
    );

    let log = serde_json::to_string(v.audit().events()).unwrap();
    assert!(log.contains("secret_released"));
    assert!(!log.contains("sk-openai-value-0001"));
    assert!(v.audit().verify().is_ok(), "the chain must still verify");
}

#[test]
fn owner_actions_are_recorded() {
    let (_d, mut v, oc) = fixture();
    call(
        &mut v,
        &oc,
        &owner(),
        Operation::Delete {
            entry: "OPENAI_API_KEY".into(),
        },
    );
    let log = serde_json::to_string(v.audit().events()).unwrap();
    assert!(log.contains("key_deleted"));
    assert!(log.contains("OPENAI_API_KEY"), "the name is not a secret");
}
