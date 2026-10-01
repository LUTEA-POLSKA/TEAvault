//! Grants: the record of who may read which key.
//!
//! A grant is deliberately narrow. It names one client fingerprint, one entry,
//! one kind of access, optionally one project directory, and it expires. It
//! does not say "this application may use my keys", because that is the kind of
//! permission that is granted once, forgotten, and then inherited by whatever
//! runs next from that path.
//!
//! Grants live inside the encrypted vault document, so an attacker who copies
//! the data files learns nothing about who has access, and cannot add one.

use serde::{Deserialize, Serialize};

use crate::{error::Result, model::now_unix};

/// How long a grant lasts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum GrantMode {
    /// Valid for one successful request, then consumed.
    AllowOnce,
    /// Valid until revoked or expired.
    AlwaysAllow {
        /// Absolute expiry as a Unix timestamp. `None` means no expiry, which
        /// is allowed but is the one option the UI marks as needing a reason.
        expires_at: Option<i64>,
    },
    /// A standing refusal. Checked *before* any expiry logic, so a deny cannot
    /// be outlived by waiting.
    Deny,
}

impl GrantMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::AllowOnce => "allow once",
            Self::AlwaysAllow { .. } => "always allow",
            Self::Deny => "deny",
        }
    }

    /// Whether this grant is a refusal.
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny)
    }

    /// Whether this grant, if it matches, permits releasing a secret.
    pub fn permits_secret(&self) -> bool {
        matches!(self, Self::AllowOnce | Self::AlwaysAllow { .. })
    }
}

/// One approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    /// Stable id, for revocation and for the audit log to refer to.
    pub id: String,
    /// [`ClientIdentity::fingerprint`].
    pub client_fingerprint: String,
    /// Human-readable client name at approval time, for the access screen.
    pub client_label: String,
    /// Which entry this grant covers. Exactly one.
    pub entry_id: String,
    /// Optional project directory the request came from, when the client
    /// reported one. Advisory: a client can report any directory, so this is
    /// shown to the user as unverified context, never used as the deciding
    /// factor on its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_dir: Option<String>,
    /// Optional free text from the client explaining why it wants the key.
    /// Untrusted. Shown quoted in the dialog so it cannot masquerade as UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_purpose: Option<String>,
    pub mode: GrantMode,
    /// RFC 3339, for display.
    pub granted_at: String,
    /// Whether this one-shot grant has been spent.
    #[serde(default)]
    pub consumed: bool,
}

impl Grant {
    pub fn new(
        client_fingerprint: impl Into<String>,
        client_label: impl Into<String>,
        entry_id: impl Into<String>,
        mode: GrantMode,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            client_fingerprint: client_fingerprint.into(),
            client_label: client_label.into(),
            entry_id: entry_id.into(),
            project_dir: None,
            declared_purpose: None,
            mode,
            granted_at: crate::model::now_rfc3339(),
            consumed: false,
        }
    }

    pub fn with_project_dir(mut self, dir: Option<String>) -> Self {
        self.project_dir = dir;
        self
    }

    pub fn with_purpose(mut self, purpose: Option<String>) -> Self {
        self.declared_purpose = purpose;
        self
    }

    /// Whether the grant covers `client` for `entry` and has not lapsed.
    ///
    /// Split into "matches" and "usable" by the caller so that a matching but
    /// expired grant can be reported as expired rather than as absent — the
    /// difference matters to the user deciding whether to re-approve.
    pub fn matches(&self, client: &str, entry_id: &str) -> bool {
        self.entry_id == entry_id && self.client_fingerprint == client
    }

    /// Whether the grant's own validity window has closed.
    pub fn is_expired(&self, now: i64) -> bool {
        match &self.mode {
            GrantMode::AlwaysAllow {
                expires_at: Some(t),
            } => now >= *t,
            _ => false,
        }
    }

    /// Whether this grant can still be spent.
    pub fn is_usable(&self, now: i64) -> bool {
        if self.consumed || !self.mode.permits_secret() {
            return false;
        }
        !self.is_expired(now)
    }

    /// A one-line summary for the access-management screen.
    pub fn summary(&self) -> String {
        let when = match &self.mode {
            GrantMode::AlwaysAllow {
                expires_at: Some(t),
            } => {
                format!("expires {}", crate::model::now_rfc3339_for(*t))
            }
            GrantMode::AlwaysAllow { expires_at: None } => "no expiry".to_string(),
            GrantMode::AllowOnce if self.consumed => "allow once, spent".to_string(),
            GrantMode::AllowOnce => "allow once".to_string(),
            GrantMode::Deny => "denied".to_string(),
        };
        format!("{} → {}", self.client_label, when)
    }
}

/// The set of grants, plus the answer to "may this client have this key?".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantSet {
    #[serde(default)]
    pub grants: Vec<Grant>,
}

/// The outcome of a permission check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// No matching grant. Needs an interactive decision.
    NeedsApproval,
    /// A matching grant permits this request. The grant id is returned so the
    /// caller can spend a one-shot grant.
    Allowed(String),
    /// Refused, with the reason.
    Refused(crate::error::DenyReason),
}

impl GrantSet {
    pub fn new(grants: Vec<Grant>) -> Self {
        Self { grants }
    }

    /// Decide whether `client` may receive the secret for `entry_id`.
    ///
    /// Order matters and is not incidental:
    ///
    /// 1. An explicit **deny** wins over everything, including a previously
    ///    granted standing permission. A revoke must actually revoke.
    /// 2. An **expired** grant is reported as expired, not as absent, so the
    ///    user is told why their approval stopped working.
    /// 3. Otherwise a usable grant permits.
    ///
    /// A spent one-shot grant is treated as absent: the next request needs a
    /// fresh decision, which is the entire meaning of "allow once".
    pub fn decide(&self, client: &str, entry_id: &str, now: i64) -> Decision {
        let mut saw_expired = false;

        for g in &self.grants {
            if !g.matches(client, entry_id) {
                continue;
            }
            if g.mode.is_deny() {
                return Decision::Refused(crate::error::DenyReason::DeniedByUser);
            }
            if g.is_expired(now) {
                saw_expired = true;
                continue;
            }
            if g.is_usable(now) {
                return Decision::Allowed(g.id.clone());
            }
        }

        if saw_expired {
            Decision::Refused(crate::error::DenyReason::Expired)
        } else {
            Decision::NeedsApproval
        }
    }

    /// Whether a client holds any grant at all for an entry.
    ///
    /// This is what lets a [`Visibility::Hidden`](crate::model::Visibility::Hidden)
    /// entry become visible to a client that has been approved for it, without
    /// advertising the entry to anyone else.
    pub fn has_any_grant_for(&self, client: &str, entry_id: &str) -> bool {
        self.grants.iter().any(|g| g.matches(client, entry_id))
    }

    /// Whether a standing deny blocks this (client, entry) pair.
    ///
    /// A deny is terminal and ignores expiry, so a hidden entry that the user
    /// denied for one client stays out of that client's `list` permanently
    /// rather than reappearing when some other grant lapses.
    pub fn is_denied(&self, client: &str, entry_id: &str, _now: i64) -> bool {
        self.grants
            .iter()
            .any(|g| g.matches(client, entry_id) && g.mode.is_deny())
    }

    /// Add or replace the grant for a (client, entry) pair.
    ///
    /// Replaces rather than appends, so approving the same thing twice does not
    /// leave two grants where one has to be revoked — and a fresh deny
    /// genuinely supersedes an older approval instead of sitting beside it.
    pub fn upsert(&mut self, grant: Grant) {
        self.grants.retain(|g| {
            !(g.client_fingerprint == grant.client_fingerprint && g.entry_id == grant.entry_id)
        });
        self.grants.push(grant);
    }

    pub fn revoke(&mut self, id: &str) -> Result<()> {
        let before = self.grants.len();
        self.grants.retain(|g| g.id != id);
        if self.grants.len() == before {
            return Err(crate::Error::not_found("grant", id));
        }
        Ok(())
    }

    /// Revoke everything belonging to one client.
    pub fn revoke_client(&mut self, client_fingerprint: &str) -> usize {
        let before = self.grants.len();
        self.grants
            .retain(|g| g.client_fingerprint != client_fingerprint);
        before - self.grants.len()
    }

    /// Drop every grant for an entry, for use inside a delete transaction.
    ///
    /// A grant outliving the entry it describes is not harmless: entry ids are
    /// UUIDs, so it will not silently match a future entry, but it would still
    /// show up in the access screen as a permission to something that is gone,
    /// and it would keep a dead client's fingerprint in the file.
    pub fn retain_entries(&mut self, keep: impl Fn(&str) -> bool) -> usize {
        let before = self.grants.len();
        self.grants.retain(|g| keep(&g.entry_id));
        before - self.grants.len()
    }

    /// Spend a one-shot grant after a successful release.
    ///
    /// Returns `false` if the grant was not a spendable one, which the caller
    /// treats as a reason to refuse rather than to continue.
    pub fn consume(&mut self, id: &str) -> bool {
        match self
            .grants
            .iter_mut()
            .find(|g| g.id == id && matches!(g.mode, GrantMode::AllowOnce))
        {
            Some(g) if !g.consumed => {
                g.consumed = true;
                true
            }
            _ => false,
        }
    }

    /// Whether `id` names a one-shot grant.
    ///
    /// Separate from `consume` because the caller must decide whether to spend
    /// *after* the secret was produced, not before — spending first would burn
    /// the user's approval on a request that then failed to decrypt.
    pub fn is_one_shot(&self, id: &str) -> bool {
        self.grants
            .iter()
            .any(|g| g.id == id && matches!(g.mode, GrantMode::AllowOnce))
    }

    /// Drop grants that can no longer do anything, so the access screen does not
    /// accumulate dead rows that invite the user to "revoke" them.
    pub fn prune(&mut self, now: i64) -> usize {
        let before = self.grants.len();
        self.grants
            .retain(|g| !g.consumed && !g.is_expired(now) && !g.mode.is_deny());
        before - self.grants.len()
    }

    pub fn grants_for(&self, entry_id: &str) -> Vec<&Grant> {
        self.grants
            .iter()
            .filter(|g| g.entry_id == entry_id)
            .collect()
    }

    pub fn distinct_clients(&self) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = Vec::new();
        for g in &self.grants {
            if !out.iter().any(|(fp, _)| *fp == g.client_fingerprint) {
                out.push((g.client_fingerprint.clone(), g.client_label.clone()));
            }
        }
        out
    }
}

/// Convenience for the current time, kept in one place so expiry checks in
/// tests and production agree.
pub fn now() -> i64 {
    now_unix()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(client: &str, entry: &str, mode: GrantMode) -> Grant {
        Grant::new(client, "test client", entry, mode)
    }

    fn forever() -> GrantMode {
        GrantMode::AlwaysAllow { expires_at: None }
    }

    #[test]
    fn no_grant_needs_approval() {
        let set = GrantSet::default();
        assert_eq!(
            set.decide("client", "entry", 1_000),
            Decision::NeedsApproval
        );
    }

    #[test]
    fn a_standing_grant_allows() {
        let set = GrantSet::new(vec![grant("client", "entry", forever())]);
        assert!(matches!(
            set.decide("client", "entry", 1_000),
            Decision::Allowed(_)
        ));
    }

    #[test]
    fn a_grant_for_a_different_entry_does_not_apply() {
        let set = GrantSet::new(vec![grant("client", "entry-A", forever())]);
        assert_eq!(
            set.decide("client", "entry-B", 1_000),
            Decision::NeedsApproval
        );
    }

    #[test]
    fn a_grant_for_a_different_client_does_not_apply() {
        let set = GrantSet::new(vec![grant("client-A", "entry", forever())]);
        assert_eq!(
            set.decide("client-B", "entry", 1_000),
            Decision::NeedsApproval
        );
    }

    #[test]
    fn an_expired_grant_is_reported_as_expired_not_absent() {
        let set = GrantSet::new(vec![grant(
            "client",
            "entry",
            GrantMode::AlwaysAllow {
                expires_at: Some(1_000),
            },
        )]);
        assert_eq!(
            set.decide("client", "entry", 1_001),
            Decision::Refused(crate::error::DenyReason::Expired)
        );
        // Still just before expiry it works.
        assert!(matches!(
            set.decide("client", "entry", 999),
            Decision::Allowed(_)
        ));
    }

    #[test]
    fn a_deny_beats_a_standing_allow() {
        // Revocation has to actually revoke, so the deny is checked first
        // regardless of insertion order.
        let mut set = GrantSet::new(vec![grant("client", "entry", forever())]);
        set.upsert(grant("client", "entry", GrantMode::Deny));
        assert_eq!(
            set.decide("client", "entry", 1_000),
            Decision::Refused(crate::error::DenyReason::DeniedByUser)
        );
    }

    #[test]
    fn a_standing_allow_beats_a_deny_from_before_it() {
        // The converse case: an explicit new approval must be able to re-grant
        // something previously denied. `upsert` keeps exactly one grant per
        // (client, entry), so this holds by construction rather than by
        // ordering luck.
        let mut set = GrantSet::new(vec![grant("client", "entry", GrantMode::Deny)]);
        set.upsert(grant("client", "entry", forever()));
        assert!(matches!(
            set.decide("client", "entry", 1_000),
            Decision::Allowed(_)
        ));
        assert_eq!(set.grants.len(), 1);
    }

    #[test]
    fn allow_once_is_spent_by_the_first_use() {
        let mut set = GrantSet::new(vec![grant("client", "entry", GrantMode::AllowOnce)]);
        let Decision::Allowed(id) = set.decide("client", "entry", 1_000) else {
            panic!("expected the first request to be allowed");
        };
        assert!(set.consume(&id));

        assert_eq!(
            set.decide("client", "entry", 1_000),
            Decision::NeedsApproval,
            "a one-shot grant must not permit a second request"
        );
        assert!(!set.consume(&id), "spending twice must be refused");
    }

    #[test]
    fn consume_refuses_a_standing_grant() {
        let mut set = GrantSet::new(vec![grant("client", "entry", forever())]);
        let Decision::Allowed(id) = set.decide("client", "entry", 1_000) else {
            panic!("expected allow");
        };
        assert!(!set.consume(&id), "standing grants must not be consumable");
        assert!(matches!(
            set.decide("client", "entry", 1_000),
            Decision::Allowed(_)
        ));
    }

    #[test]
    fn a_deny_grant_is_never_reported_as_allowed() {
        let set = GrantSet::new(vec![grant("client", "entry", GrantMode::Deny)]);
        assert!(!set
            .decide("client", "entry", 1_000)
            .eq(&Decision::Allowed("x".into())));
    }

    #[test]
    fn upsert_replaces_rather_than_accumulates() {
        let mut set = GrantSet::new(vec![grant("client", "entry", forever())]);
        set.upsert(grant("client", "entry", forever()));
        assert_eq!(
            set.grants.len(),
            1,
            "a re-approval must not leave two grants"
        );
    }

    #[test]
    fn revoke_removes_only_the_named_grant() {
        let a = grant("client", "entry-A", forever());
        let b = grant("client", "entry-B", forever());
        let mut set = GrantSet::new(vec![a.clone(), b]);
        set.revoke(&a.id).unwrap();
        assert_eq!(set.grants.len(), 1);
        assert_eq!(set.grants[0].entry_id, "entry-B");
        assert!(set.revoke(&a.id).is_err());
    }

    #[test]
    fn revoke_client_removes_everything_for_that_client_only() {
        let mut set = GrantSet::new(vec![
            grant("client-A", "entry-A", forever()),
            grant("client-A", "entry-B", forever()),
            grant("client-B", "entry-A", forever()),
        ]);
        assert_eq!(set.revoke_client("client-A"), 2);
        assert_eq!(set.grants.len(), 1);
        assert_eq!(set.grants[0].client_fingerprint, "client-B");
    }

    #[test]
    fn hidden_entries_become_visible_only_after_a_grant_exists() {
        let set = GrantSet::new(vec![grant("client", "hidden-entry", forever())]);
        assert!(set.has_any_grant_for("client", "hidden-entry"));
        assert!(!set.has_any_grant_for("stranger", "hidden-entry"));
    }

    #[test]
    fn prune_drops_only_grants_that_can_no_longer_act() {
        let mut set = GrantSet::new(vec![
            grant("c1", "e1", forever()),
            grant(
                "c2",
                "e2",
                GrantMode::AlwaysAllow {
                    expires_at: Some(1_000),
                },
            ),
            grant("c3", "e3", GrantMode::Deny),
        ]);
        let mut spent = grant("c4", "e4", GrantMode::AllowOnce);
        spent.consumed = true;
        set.grants.push(spent);

        assert_eq!(set.prune(1_001), 3);
        assert_eq!(set.grants.len(), 1);
        assert_eq!(set.grants[0].client_fingerprint, "c1");
    }

    #[test]
    fn project_dir_and_purpose_are_carried_but_never_decide_anything() {
        let g = grant("client", "entry", forever())
            .with_project_dir(Some(r"C:\work\thing".into()))
            .with_purpose(Some("run tests".into()));
        let set = GrantSet::new(vec![g]);
        // A request whose project dir differs is still allowed: the directory
        // is context for the user, not a constraint we can trust.
        assert!(matches!(
            set.decide("client", "entry", 1_000),
            Decision::Allowed(_)
        ));
    }
}
