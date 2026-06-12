//! `cloak deny <SECRET> <HOST>`: revoke a secret's permission to reach a
//! host via `proxy_authenticated_http_request`.
//!
//! The inverse of `cloak allow`: removes `HOST` from the secret's
//! `allowed_hosts`, persists atomically (preserving comments), and asks
//! the running `cloakd` to reload. If the secret rule or the host isn't
//! present, nothing is written and we say so (still exit 0).

use anyhow::{Context as _, Result};
use serde_json::json;
use toml_edit::DocumentMut;

use cloak_core::policy::default_policy_path;

use super::daemon::atomic_write_with_backup;
use super::daemon_ipc::{call_daemon, is_daemon_down};
use super::policy_edit::{deny_host, DenyOutcome};
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

    match deny_host(&mut doc, secret, host) {
        DenyOutcome::NotPresent => {
            println!("nothing to remove: {secret} does not allow {host}");
            Ok(())
        }
        DenyOutcome::Removed => {
            atomic_write_with_backup(&path, doc.to_string().as_bytes(), 0o600)?;
            match call_daemon("policy.reload", json!({})) {
                Ok(_) => println!("denied {secret} -> {host} (live)"),
                Err(e) if is_daemon_down(&e) => {
                    println!(
                        "denied {secret} -> {host} (saved; applies when cloakd next starts)"
                    );
                }
                Err(e) => {
                    println!("denied {secret} -> {host} (saved)");
                    eprintln!("warning: live policy reload failed: {e}");
                }
            }
            Ok(())
        }
    }
}
