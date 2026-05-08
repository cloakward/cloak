//! `cloak backup mnemonic` and `cloak backup verify`.
//!
//! - `mnemonic` re-displays the 24-word recovery seed for a vault. The
//!   mnemonic is **not** stored anywhere by Cloak; what we actually do
//!   is unwrap the master key under the passphrase, then walk a
//!   challenge-style flow: there is no path to print the original
//!   words because we never kept them. So `mnemonic` instead surfaces
//!   the disposition: a vault that was created with a recovery wrap
//!   confirms the wrap exists; vaults that pre-date the feature get a
//!   typed error pointing at v1.1 migration. To actually re-display
//!   the words, the user needs the original printout. (See
//!   THREAT_MODEL.md "show-once recovery seed".)
//!
//! - `verify` reads the user's words from stdin and round-trips them
//!   against the stored recovery wrap. No restoration; just a yes/no.

use std::io::{self, BufRead, IsTerminal};

use anyhow::{Context as _, Result};
use cloak_core::audit::AuditResult;
use cloak_core::recovery::RecoveryMnemonic;
use cloak_core::Error;

use super::audit_log;
use super::{open_vault, unlock::unlock_interactive, Context, SystemError};
use crate::biometric_macos;

/// `cloak backup mnemonic`. The phrase itself is not stored — Cloak
/// shows it once at creation and never again. This command surfaces
/// that contract: it confirms the vault carries a recovery wrap (so a
/// pre-v1.0 vault can be detected) and reminds the user where to find
/// the original printout.
pub fn run_mnemonic(ctx: &Context) -> Result<()> {
    let mut vault = open_vault(ctx)?;
    if !vault.is_initialized()? {
        return Err(SystemError::boxed(format!(
            "vault not initialized at {}",
            ctx.vault_path.display()
        )));
    }
    if !vault.has_recovery_wrap()? {
        audit_log::append(
            "cli.backup.mnemonic",
            None,
            AuditResult::Error,
            Some("vault has no recovery wrap (pre-v1.0)".into()),
        );
        return Err(Error::NoRecoveryWrap.into());
    }

    // Privileged path: require unlock + Touch ID before we even confirm
    // the wrap exists. This keeps a same-UID attacker from polling the
    // command to learn whether a vault is recoverable.
    unlock_interactive(&mut vault)?;
    if !ctx.no_biometric {
        let reason = "Confirm access to the Cloak recovery seed metadata";
        match biometric_macos::authenticate(reason) {
            Ok(true) => {}
            Ok(false) => {
                audit_log::append(
                    "cli.backup.mnemonic",
                    None,
                    AuditResult::Error,
                    Some("biometric refused".into()),
                );
                anyhow::bail!("biometric authentication failed");
            }
            Err(e) => {
                audit_log::append(
                    "cli.backup.mnemonic",
                    None,
                    AuditResult::Error,
                    Some(format!("biometric error: {e}")),
                );
                anyhow::bail!("biometric authentication failed");
            }
        }
    }

    println!("This vault carries a 24-word BIP-39 recovery seed.");
    println!();
    println!("Cloak does NOT keep a copy of the words. They were displayed once at");
    println!("vault creation; you should have a paper copy stored offline.");
    println!();
    println!("If you have the words: confirm them with `cloak backup verify`.");
    println!("If you have lost the words but still know the passphrase: there is no");
    println!("way to re-display them — create a new vault with a fresh seed and");
    println!("re-import your secrets.");

    audit_log::append(
        "cli.backup.mnemonic",
        None,
        AuditResult::Ok,
        Some("recovery wrap presence confirmed".into()),
    );
    Ok(())
}

/// `cloak backup verify`. Reads the user's words from stdin and
/// confirms they round-trip the stored recovery wrap. Touch ID gated:
/// like `cloak show`, this is privileged because it confirms whether a
/// supplied seed unlocks the vault.
pub fn run_verify(ctx: &Context) -> Result<()> {
    let vault = open_vault(ctx)?;
    if !vault.is_initialized()? {
        return Err(SystemError::boxed(format!(
            "vault not initialized at {}",
            ctx.vault_path.display()
        )));
    }
    if !vault.has_recovery_wrap()? {
        audit_log::append(
            "cli.backup.verify",
            None,
            AuditResult::Error,
            Some("vault has no recovery wrap".into()),
        );
        return Err(Error::NoRecoveryWrap.into());
    }

    println!("Type or paste the 24 words. Whitespace and case are ignored.");
    println!("Press Ctrl-D (or just Enter on a blank line) when done.");
    println!();
    let raw = read_mnemonic_input()?;
    let mnemonic = match RecoveryMnemonic::parse(&raw) {
        Ok(m) => m,
        Err(_) => {
            audit_log::append(
                "cli.backup.verify",
                None,
                AuditResult::Error,
                Some("invalid mnemonic supplied".into()),
            );
            return Err(Error::InvalidMnemonic.into());
        }
    };
    match vault.verify_mnemonic(&mnemonic) {
        Ok(()) => {
            println!("OK: the seed you entered matches this vault.");
            audit_log::append(
                "cli.backup.verify",
                None,
                AuditResult::Ok,
                Some("mnemonic round-trip OK".into()),
            );
            Ok(())
        }
        Err(e) => {
            audit_log::append(
                "cli.backup.verify",
                None,
                AuditResult::Error,
                Some("mnemonic did not match stored recovery wrap".into()),
            );
            Err(e.into())
        }
    }
}

fn read_mnemonic_input() -> Result<String> {
    if let Ok(s) = std::env::var("CLOAK_MNEMONIC") {
        return Ok(s);
    }
    let stdin = io::stdin();
    let interactive = stdin.is_terminal();
    let mut acc = String::new();
    let lock = stdin.lock();
    for line in lock.lines() {
        let line = line.context("read mnemonic from stdin")?;
        if interactive && line.trim().is_empty() {
            break;
        }
        if !acc.is_empty() {
            acc.push(' ');
        }
        acc.push_str(line.trim());
    }
    Ok(acc)
}
