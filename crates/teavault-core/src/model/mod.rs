//! Domain model.
//!
//! Two rules shape this module:
//!
//! * **Provider names and capabilities are metadata, not evidence.** Nothing
//!   here claims that a key labelled `OpenAI` is an OpenAI key, that it is
//!   valid, or that it works. TEAvault never contacts a provider to find out,
//!   because a validation request would hand the secret to a network it does
//!   not control. The labels are the user's own description of their own key.
//! * **A secret is not a field of this struct.** [`ApiKeyMetadata`] has no
//!   secret field at all, so a metadata DTO cannot leak one even by accident.
//!   The secret lives in [`StoredSecret`] and reaches a caller only through
//!   the permission-gated request path.

pub mod client;
pub mod grant;

pub use client::ClientIdentity;
pub use grant::{Decision, Grant, GrantMode, GrantSet};

use serde::{Deserialize, Serialize};

/// A well-known provider label. Free-form strings are also accepted; this enum
/// exists so the common cases can be offered as a list in the UI without a
/// hardcoded array in the frontend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnownProvider {
    OpenAi,
    Anthropic,
    Groq,
    GitHub,
    Cloudflare,
    /// Anything the user typed.
    Other,
}

impl KnownProvider {
    /// Default capabilities for a provider, offered as a starting point in the
    /// editor. Advisory only — the user edits them freely.
    pub fn suggested_capabilities(&self) -> &'static [&'static str] {
        match self {
            Self::OpenAi | Self::Anthropic | Self::Groq => &["llm", "embeddings"],
            Self::GitHub => &["source", "ci"],
            Self::Cloudflare => &["dns", "workers", "storage"],
            Self::Other => &[],
        }
    }
}

/// What a client can learn about an entry from `list` and `info`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKeyMetadata {
    /// Opaque identifier. Stable for the life of the entry.
    pub id: String,
    /// Environment-variable-style name, e.g. `OPENAI_API_KEY`. Unique.
    pub name: String,
    /// Human label for the UI.
    pub display_name: String,
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Free-form capability tags. Metadata, never enforced.
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    /// Whether an ungranted client may see this entry in `list`.
    pub visibility: Visibility,
}

/// Whether an entry is advertised to clients that hold no grant for it.
///
/// This is the knob that makes "agents can discover keys without receiving
/// them" safe to offer: a discoverable entry's *name* is public to any local
/// client, while its *value* still requires an explicit grant. An entry set to
/// [`Visibility::Hidden`] is not listed at all until a grant for it exists —
/// so the inventory itself is not disclosed to an unapproved process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    #[default]
    /// Appears in `list` for any client; `request` still needs a grant.
    Discoverable,
    /// Does not appear in `list` unless the client already holds a grant.
    Hidden,
}

/// An entry's secret, as it exists on disk: opaque ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSecret {
    pub entry_id: String,
    pub sealed: crate::crypto::aead::Sealed,
}

/// A validated variable name. Uppercase, digits and underscores, starting with
/// a letter — the shape every tool already expects of an environment variable.
///
/// Checked rather than trimmed, because a name with a stray space would break
/// every downstream consumer in a way that is very hard to trace back.
pub fn validate_var_name(name: &str) -> crate::Result<()> {
    use crate::error::Error;
    if name.is_empty() {
        return Err(Error::invalid("name", "must not be empty"));
    }
    if name.len() > 128 {
        return Err(Error::invalid("name", "must be at most 128 characters"));
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return Err(Error::invalid(
            "name",
            "must start with a letter or underscore",
        ));
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || *c == '_'))
    {
        return Err(Error::invalid(
            "name",
            format!("must contain only letters, digits and underscores (found {bad:?})"),
        ));
    }
    Ok(())
}

/// Provider display name for a stored string, falling back to `Other`.
pub fn known_provider(s: &str) -> KnownProvider {
    match s.to_ascii_lowercase().as_str() {
        "openai" => KnownProvider::OpenAi,
        "anthropic" => KnownProvider::Anthropic,
        "groq" => KnownProvider::Groq,
        "github" => KnownProvider::GitHub,
        "cloudflare" => KnownProvider::Cloudflare,
        _ => KnownProvider::Other,
    }
}

/// Current time as RFC 3339, for storage and display.
///
/// Display only. Nothing in the security model compares timestamps against a
/// trusted clock, because the local clock is under the same control as
/// everything else on the machine. Grant expiry is checked against this clock
/// and is documented as such in `THREAT_MODEL.md`.
pub fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Seconds since the Unix epoch, for expiry arithmetic.
pub fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// Render a Unix timestamp as RFC 3339, for grant expiry display.
pub fn now_rfc3339_for(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| format!("unix:{unix}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn var_names_are_restricted_to_environment_variable_shape() {
        for good in ["OPENAI_API_KEY", "GROQ_API_KEY", "_PRIVATE", "a1"] {
            assert!(validate_var_name(good).is_ok(), "{good} should be valid");
        }
        for bad in [
            "",
            "1BAD",
            "has space",
            "has-dash",
            "emoji🎉",
            &"x".repeat(129),
        ] {
            assert!(
                validate_var_name(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn metadata_has_no_field_that_could_hold_a_secret() {
        // A structural guarantee, so "list never returns secrets" does not
        // depend on remembering to strip a field at every call site.
        let json = serde_json::to_string(&ApiKeyMetadata {
            id: "id".into(),
            name: "OPENAI_API_KEY".into(),
            display_name: "OpenAI".into(),
            provider: "OpenAI".into(),
            description: None,
            capabilities: vec!["llm".into()],
            created_at: now_rfc3339(),
            updated_at: now_rfc3339(),
            visibility: Visibility::Discoverable,
        })
        .unwrap();
        assert!(!json.contains("secret"));
        assert!(!json.contains("value"));
    }
}
