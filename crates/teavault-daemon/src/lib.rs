//! TEAvault background process.
//!
//! Split into a library and a thin binary so the pipe server, the identity
//! resolution and the clipboard can be integration-tested without starting a
//! tray icon. The binary does argument handling and the message loop; everything
//! testable is here.

pub mod audit_key;
pub mod clipboard;
pub mod pipe;
pub mod server;
pub mod tray;

pub use server::{serve_forever, Shared};
