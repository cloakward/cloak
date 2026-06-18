//! `cloak allow <SECRET> <HOST>`: grant a secret permission to reach a
//! host via `proxy_authenticated_http_request`.
//!
//! The rule is persisted to the policy file (atomically, preserving
//! comments) and then a live reload is requested from the running
//! `cloakd`. If the daemon is down the rule is still saved and applies on
//! the daemon's next start.

use anyhow::{Context as _, Result};
use serde_json::json;
use toml_edit::DocumentMut;

use cloak_core::policy::default_policy_path;

use super::daemon::atomic_write_with_backup;
use super::daemon_ipc::{call_daemon, is_daemon_down};
use super::policy_edit::{allow_host, AllowOutcome};
use super::{Context, SystemError};

pub fn run(_ctx: &Context, secret: &str, host: &str) -> Result<()> {
    let path = default_policy_path();
    if !path.exists() {
        return Err(SystemError::boxed(format!(
            "no policy file at {}: run `cloak setup` first",
            path.display()
        )));
    }

    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("read policy {}", path.display()))?;
    let mut doc = raw
        .parse::<DocumentMut>()
        .with_context(|| format!("parse policy {}", path.display()))?;

    let outcome = allow_host(&mut doc, secret, host);
    if outcome == AllowOutcome::AlreadyPresent {
        println!("{secret} -> {host} already allowed (no change)");
        // Nothing changed on disk, so there is no reload to do: the live and
        // on-disk policy already agree on this host.
    } else {
        atomic_write_with_backup(&path, doc.to_string().as_bytes(), 0o600)?;
    }

    reload_and_report(secret, host, outcome);
    Ok(())
}

/// Ask the daemon to reload and print a status line. A down daemon is not
/// an error: the rule is already on disk.
fn reload_and_report(secret: &str, host: &str, outcome: AllowOutcome) {
    if outcome == AllowOutcome::AlreadyPresent {
        // Nothing was written; only report reload state for new edits.
        return;
    }
    match call_daemon("policy.reload", json!({})) {
        Ok(_) => println!("allowed {secret} -> {host} (live)"),
        Err(e) if is_daemon_down(&e) => {
            println!("allowed {secret} -> {host} (saved; applies when cloakd next starts)");
        }
        Err(e) => {
            println!("allowed {secret} -> {host} (saved)");
            eprintln!("warning: live policy reload failed: {e}");
        }
    }
}
