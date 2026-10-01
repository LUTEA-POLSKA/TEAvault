//! Entry point for the TEAvault desktop UI.
//!
//! The whole application lives in the library so it can be reviewed without a
//! window; this exists only so Cargo has a binary to build.

fn main() {
    teavault_app_lib::run()
}
