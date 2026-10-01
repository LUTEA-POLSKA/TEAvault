//! Client identity.
//!
//! A client is identified by what the operating system can prove, not by what
//! it claims. The pipe server asks Windows for the PID on the other end of the
//! connection ([`ClientIdentity::from_server`]) and resolves the image path
//! from that handle. Everything in the request body — a `client_name`, a
//! `purpose` string, a claimed path — is treated as untrusted text to display,
//! never as an identity to authorise on.
//!
//! ## What a process path does and does not prove
//!
//! A path is *not* an identity proof. A malicious process running as the user
//! can be named anything, can be launched from any directory, and can be
//! replaced on disk after the user approved it. So a path is used only to:
//!
//! * **display** to the user in the confirmation dialog, and
//! * **key** a grant, so that revoking by path is possible.
//!
//! The PID additionally distinguishes concurrent clients, but it is also not
//! trusted for authorisation: PIDs are reused, and a PID alone would let any
//! process claim to be a previously-approved one.
//!
//! What actually stops an unapproved local process is
//! ([`crate::policy`]):
//!
//! 1. no grant exists for it, so `request` is refused, and
//! 2. a grant only comes into existence through an explicit, interactive
//!    decision, and
//! 3. every refusal and every approval is in the audit log.
//!
//! See `THREAT_MODEL.md` for the residual risk of an attacker who already runs
//! code as the user: they can wait for the user to approve a dialog, and no
//! amount of local design prevents that. What the design does prevent is that
//! attack being silent and unattended.

use serde::{Deserialize, Serialize};

/// Who is asking, as far as Windows can tell us.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientIdentity {
    /// Process ID reported by the kernel for the pipe connection. Never
    /// trusted for authorisation on its own.
    pub pid: u32,
    /// Full image path resolved from the process handle.
    pub image_path: String,
    /// File name, for compact display.
    pub file_name: String,
    /// True when the process's token is elevated (runs as an administrator).
    /// Shown to the user, because an elevated caller asking for a key is worth
    /// noticing.
    pub elevated: bool,
}

impl ClientIdentity {
    pub fn new(pid: u32, image_path: impl Into<String>) -> Self {
        let image_path = image_path.into();
        let file_name = image_path
            .rsplit(['\\', '/'])
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("unknown")
            .to_string();
        Self {
            pid,
            image_path,
            file_name,
            elevated: false,
        }
    }

    /// The durable identity a grant is bound to.
    ///
    /// Deliberately excludes the PID and the elevation flag. If the PID were
    /// part of the grant, approving `node.exe` from one project would not
    /// approve the next `node.exe`, and the user would be prompted forever; if
    /// it were the only thing checked, every process on the machine could
    /// claim to be an approved one.
    pub fn fingerprint(&self) -> String {
        // The whole fingerprint is lower-cased: Windows paths are
        // case-insensitive, so `C:\Tools\agent.exe` and `c:\tools\AGENT.EXE`
        // must not become two separate grants. Lower-casing the entire value
        // rather than just the file name is what makes that true.
        format!("{}|{}", self.file_name, self.image_path).to_ascii_lowercase()
    }

    /// A short label for dialogs and log lines.
    pub fn describe(&self) -> String {
        format!("{} (PID {})", self.file_name, self.pid)
    }
}

impl std::fmt::Display for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.image_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_ignores_the_pid_so_a_restart_does_not_invalidate_a_grant() {
        let a = ClientIdentity::new(1234, r"C:\Program Files\Code\Code.exe");
        let b = ClientIdentity::new(9999, r"C:\Program Files\Code\Code.exe");
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn fingerprint_distinguishes_different_paths_with_the_same_name() {
        let a = ClientIdentity::new(1, r"C:\tools\a\agent.exe");
        let b = ClientIdentity::new(1, r"C:\other\a\agent.exe");
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn fingerprint_is_case_insensitive_on_windows_paths() {
        // Windows paths are case-insensitive, so two spellings of one path must
        // not produce two different grants.
        let a = ClientIdentity::new(1, r"C:\Tools\Agent.EXE");
        let b = ClientIdentity::new(2, r"c:\tools\agent.exe");
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn file_name_is_extracted_from_both_separators() {
        assert_eq!(
            ClientIdentity::new(1, r"C:\a\b\app.exe").file_name,
            "app.exe"
        );
        assert_eq!(ClientIdentity::new(1, "/usr/local/app").file_name, "app");
        assert_eq!(ClientIdentity::new(1, "").file_name, "unknown");
    }

    #[test]
    fn describe_never_contains_a_secret_because_there_is_no_secret_field() {
        let id = ClientIdentity::new(42, r"C:\x\y.exe");
        assert_eq!(id.describe(), "y.exe (PID 42)");
    }
}
