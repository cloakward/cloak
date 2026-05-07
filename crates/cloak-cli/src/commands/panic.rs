//! `cloak panic` — emergency lockdown.
//!
//! Walk-through:
//! 1. Append a `cli.panic` audit entry naming every secret in the vault
//!    so the chain shows exactly what was at risk at this point in time.
//! 2. Stop the daemon (`launchctl unload` / `systemctl --user disable`),
//!    which kills every live MCP/CLI session.
//! 3. Print a rotation worksheet to stdout the user can paste into their
//!    incident-response notes.

use anyhow::Result;
use cloak_core::audit::AuditResult;

use super::audit_log;
use super::daemon as daemonctl;
use super::{open_vault, Context};

pub fn run(ctx: &Context) -> Result<()> {
    let vault = open_vault(ctx)?;
    let names: Vec<String> = if vault.is_initialized().unwrap_or(false) {
        vault.list().unwrap_or_default().into_iter().map(|m| m.name).collect()
    } else {
        Vec::new()
    };

    // 1. Audit-log every secret name. We don't reveal plaintext.
    audit_log::append(
        "cli.panic",
        None,
        AuditResult::Ok,
        Some(format!("vault contains {} secret(s)", names.len())),
    );
    for n in &names {
        audit_log::append(
            "cli.panic",
            Some(n),
            AuditResult::Ok,
            Some("listed-during-panic".into()),
        );
    }

    // 2. Stop the daemon (kills every live session).
    if let Err(e) = daemonctl::stop_daemon() {
        eprintln!("warning: could not stop daemon: {e}");
    } else {
        eprintln!("daemon stopped (all sessions revoked)");
    }

    // 3. Rotation worksheet.
    println!("# Cloak panic — rotation worksheet");
    println!("# Generated: {}", chrono::Utc::now().to_rfc3339());
    println!("# Daemon: stopped. Re-enable with `cloak daemon start`.");
    println!();
    if names.is_empty() {
        println!("(vault is empty — nothing to rotate)");
        return Ok(());
    }
    println!("Rotate every secret below. Tick each off as you regenerate it");
    println!("at the upstream provider and update Cloak with `cloak set NAME`:");
    println!();
    for n in &names {
        println!("  [ ] {n}");
    }
    println!();
    println!("After rotating, run `cloak daemon start` to bring the daemon back up.");
    Ok(())
}
