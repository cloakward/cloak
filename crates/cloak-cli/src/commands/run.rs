//! `cloak run [--only KEY1,KEY2] -- COMMAND` — run a child process with
//! vault secrets injected as environment variables.
//!
//! ## Security boundary
//! - Goes through the same biometric-gated unlock+show path as
//!   `cloak show`: unlock the vault locally, prompt Touch ID / polkit,
//!   then decrypt per-record via the existing `Vault::show` API.
//! - Secrets are passed to the child via `Command::env`. We never write
//!   them to disk and never echo them to stdout.
//! - On exit, `Secret<String>`s drop and zeroize. The OS still has a
//!   copy in the child's environment; that is the user's chosen trade.
//! - Audit-logs `tool = "cli.run"` per secret with the secret name +
//!   caller pid.

use std::ffi::OsString;
use std::process::{Command, ExitCode};

use anyhow::Result;

use super::audit_log;
use super::{open_vault, unlock::unlock_interactive, Context};
use crate::biometric_macos;

pub fn run(
    ctx: &Context,
    only: Vec<String>,
    cmdline: Vec<OsString>,
) -> Result<ExitCode> {
    if cmdline.is_empty() {
        anyhow::bail!("usage: cloak run [--only K1,K2] -- COMMAND [ARG ...]");
    }

    let mut vault = open_vault(ctx)?;
    if !vault.is_initialized()? {
        anyhow::bail!("vault not initialized — run `cloak setup` first");
    }
    unlock_interactive(&mut vault)?;

    if !ctx.no_biometric {
        let reason = if only.is_empty() {
            "Inject Cloak secrets into a subprocess".to_string()
        } else {
            format!("Inject {} Cloak secret(s) into a subprocess", only.len())
        };
        match biometric_macos::authenticate(&reason) {
            Ok(true) => {}
            Ok(false) => anyhow::bail!("biometric authentication failed"),
            Err(e) => anyhow::bail!("biometric authentication failed: {e}"),
        }
    }

    let names: Vec<String> = if only.is_empty() {
        vault.list()?.into_iter().map(|m| m.name).collect()
    } else {
        only
    };

    // Resolve plaintexts up-front so we can drop the vault before exec.
    let mut env_pairs: Vec<(String, cloak_core::crypto::Secret<String>)> =
        Vec::with_capacity(names.len());
    for n in &names {
        let s = vault.show(n)?;
        audit_log::append(
            "cli.run",
            Some(n),
            cloak_core::audit::AuditResult::Ok,
            Some(format!("argv0={}", cmdline[0].to_string_lossy())),
        );
        env_pairs.push((n.clone(), s));
    }
    drop(vault);

    let (program, args) = cmdline.split_first().unwrap();
    let mut child = Command::new(program);
    child.args(args);
    for (k, v) in &env_pairs {
        child.env(k, v.expose_secret());
    }
    // Inherit the rest of stdin/stdout/stderr — aws-vault style.
    let status = child.status().map_err(|e| {
        anyhow::anyhow!("failed to spawn {}: {e}", program.to_string_lossy())
    })?;

    // Explicitly drop now so zeroize-on-drop runs before we return.
    drop(env_pairs);

    if let Some(code) = status.code() {
        // Map child exit code 0..=255 directly to our ExitCode.
        Ok(ExitCode::from(code.clamp(0, 255) as u8))
    } else {
        Ok(ExitCode::FAILURE)
    }
}
