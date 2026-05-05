//! `cloak` CLI binary entry point.
//!
//! Implementation lives in modules under `src/`. This file is just the
//! `main()` shim that builds the clap command and dispatches.

// `biometric_macos` ships both a real macOS impl and a non-macOS stub
// inside the same file (gated internally), so the module is declared
// unconditionally; gating it at the `mod` line breaks the Linux build
// because `commands::show` imports it on every target.
mod biometric_macos;
mod commands;
mod prompt;

use std::process::ExitCode;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("cloak=info")),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    match commands::run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
