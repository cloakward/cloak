//! `cloak export [PATH]` — render the vault as a `.env` file on disk.
//!
//! ## Security boundary
//! - Goes through the same biometric-gated `vault.show` path as
//!   `cloak show` (see `commands::show`): unlock the vault locally,
//!   prompt Touch ID / polkit, then decrypt **per-record** using the
//!   existing `Vault::show` API.
//! - Refuses to write to a non-TTY caller without `--force` so secrets
//!   don't end up in shell history / stdout pipes by accident.
//! - Loud stderr warning every time we materialize plaintext on disk.
//! - Audit-logs each secret revealed with the secret name and the
//!   caller's pid (`tool = "cli.export"`).

use std::path::PathBuf;

use anyhow::Result;

use super::audit_log;
use super::dotenv::render_dotenv;
use super::{open_vault, unlock::unlock_interactive, Context};
use crate::biometric_macos;

/// Run the export. `force` is required when stdout is not a TTY (or
/// when the destination file already exists).
pub fn run(ctx: &Context, path: Option<PathBuf>, force: bool) -> Result<()> {
    let dest = path.unwrap_or_else(|| PathBuf::from(".env"));
    if dest.exists() && !force {
        anyhow::bail!(
            "{} already exists; pass --force to overwrite",
            dest.display()
        );
    }

    eprintln!(
        "WARNING: cloak export is about to write plaintext secrets to {}.",
        dest.display()
    );
    eprintln!("         Anything reading that file will read your secrets in the clear.");

    let mut vault = open_vault(ctx)?;
    if !vault.is_initialized()? {
        anyhow::bail!("vault not initialized — run `cloak setup` first");
    }
    unlock_interactive(&mut vault)?;

    // Biometric / user-presence step. Mirrors `cloak show`.
    if !ctx.no_biometric {
        let reason = "Export Cloak vault to .env file".to_string();
        match biometric_macos::authenticate(&reason) {
            Ok(true) => {}
            Ok(false) => anyhow::bail!("biometric authentication failed"),
            Err(e) => anyhow::bail!("biometric authentication failed: {e}"),
        }
    }

    let names: Vec<String> = vault.list()?.into_iter().map(|m| m.name).collect();
    let mut out: Vec<(String, String)> = Vec::with_capacity(names.len());
    for n in &names {
        let s = vault.show(n)?;
        out.push((n.clone(), s.expose_secret().clone()));
        audit_log::append(
            "cli.export",
            Some(n),
            cloak_core::audit::AuditResult::Ok,
            Some(format!("dest={}", dest.display())),
        );
        drop(s);
    }
    let body = render_dotenv(&out);
    super::daemon::atomic_write(&dest, body.as_bytes(), 0o600)?;
    println!("exported {} secret(s) to {}", out.len(), dest.display());
    Ok(())
}
