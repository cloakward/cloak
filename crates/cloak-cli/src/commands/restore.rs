//! `cloak restore` — re-derive vault access from a 24-word mnemonic.
//!
//! When a user has lost their vault passphrase but still has the BIP-39
//! recovery seed they wrote down at vault creation, this command walks
//! them through:
//!
//! 1. Reading the 24 words from stdin (one big multi-line read; we
//!    accept any whitespace separators and case).
//! 2. Validating against the BIP-39 wordlist + checksum.
//! 3. Deriving the recovery key and unwrapping the master key from the
//!    `meta.recovery_wrap_*` blob.
//! 4. Prompting for a NEW passphrase (twice).
//! 5. Re-wrapping the master key under the new passphrase + pepper and
//!    persisting the new wrap, leaving the recovery wrap intact.
//!
//! On success the vault is unlocked: subsequent commands can run in the
//! same process without re-entering the new passphrase. Touch ID is
//! NOT required here — possession of the mnemonic is the auth factor.

use std::io::{self, BufRead, IsTerminal};

use anyhow::{Context as _, Result};
use cloak_core::audit::AuditResult;
use cloak_core::recovery::RecoveryMnemonic;
use cloak_core::Error;

use super::audit_log;
use super::{open_vault, Context, SystemError};
use crate::prompt::prompt_passphrase_twice;

/// Run `cloak restore [PATH]`. The path resolution lives in the
/// dispatcher; we just operate on whatever vault `ctx.vault_path`
/// points at.
pub fn run(ctx: &Context) -> Result<()> {
    let mut vault = open_vault(ctx)?;
    if !vault.is_initialized()? {
        return Err(SystemError::boxed(format!(
            "vault not initialized at {} — `cloak restore` only operates \
             on existing vaults that already carry a recovery seed",
            ctx.vault_path.display()
        )));
    }
    if !vault.has_recovery_wrap()? {
        return Err(Error::NoRecoveryWrap.into());
    }

    println!("Cloak restore: re-derive vault access from your 24-word seed.");
    println!();
    println!("Enter the 24 words now. Separate by spaces or newlines; case is ignored.");
    println!("Press Ctrl-D (or just Enter on a blank line) when done.");
    println!();

    let raw = read_mnemonic_input()?;
    let mnemonic = match RecoveryMnemonic::parse(&raw) {
        Ok(m) => m,
        Err(_) => {
            audit_log::append(
                "cli.restore",
                None,
                AuditResult::Error,
                Some("invalid mnemonic supplied".into()),
            );
            return Err(Error::InvalidMnemonic.into());
        }
    };

    // Up-front round-trip: confirm the mnemonic actually unwraps the
    // recovery blob *before* we ask for a new passphrase. Saves the
    // user typing a fresh passphrase twice and then learning they
    // mistyped a word.
    if let Err(e) = vault.verify_mnemonic(&mnemonic) {
        audit_log::append(
            "cli.restore",
            None,
            AuditResult::Error,
            Some("mnemonic did not match stored recovery wrap".into()),
        );
        return Err(e.into());
    }

    println!("Mnemonic accepted. Choose a NEW passphrase for the vault.");
    let new_pass = prompt_passphrase_twice()?;

    let params = vault.restore_with_mnemonic(&mnemonic, &new_pass)?;
    println!("Vault restored.");
    println!(
        "  kdf: argon2id (m={} KiB, t={}, p={})",
        params.mem_kib, params.t_cost, params.p_cost
    );
    println!();
    println!("Your old passphrase is now invalid. Use the new one for `cloak unlock`.");
    audit_log::append(
        "cli.restore",
        None,
        AuditResult::Ok,
        Some("master re-wrapped under fresh passphrase".into()),
    );
    Ok(())
}

/// Read the mnemonic from stdin. Honors `CLOAK_MNEMONIC` for tests so
/// `assert_cmd` cases don't need to wrangle stdin; in interactive mode
/// it reads until EOF or a blank line.
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
