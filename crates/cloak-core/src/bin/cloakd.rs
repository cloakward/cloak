//! `cloakd` — the privileged daemon binary.
//!
//! Runs the IPC listener, owns the vault, performs all egress.
//! See `cloak_core::daemon` for the implementation.

use std::process::ExitCode;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("cloakd=info,cloak_core=info")
            }),
        )
        .with_target(false)
        .init();

    #[cfg(unix)]
    {
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("cloakd: failed to start tokio: {e}");
                return ExitCode::from(2);
            }
        };
        match rt.block_on(cloak_core::daemon::run()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                tracing::error!(error = %e, "cloakd exited with error");
                ExitCode::FAILURE
            }
        }
    }

    #[cfg(not(unix))]
    {
        eprintln!("cloakd: only Unix platforms are supported in v0.1");
        ExitCode::from(2)
    }
}
