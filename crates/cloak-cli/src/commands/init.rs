//! `cloak init` — create a fresh vault.

use anyhow::Result;
use cloak_core::audit::AuditResult;

use super::audit_log;
use super::recovery_display::print_mnemonic_warning;
use super::{open_vault, Context, SystemError};
use crate::prompt::prompt_passphrase_twice;

/// Initialize a new vault at `ctx.vault_path`. Refuses if one already
/// exists at that path. Prompts for the passphrase twice (or reads
/// `CLOAK_PASSPHRASE` for tests) and then prints the autotuned KDF
/// parameters so the user has a record of what their vault uses.
///
/// Also generates and prints a 24-word BIP-39 recovery mnemonic ONCE.
/// Cloak does not keep a copy; the user must write the words down.
pub fn run(ctx: &Context) -> Result<()> {
    let mut vault = open_vault(ctx)?;
    if vault.is_initialized()? {
        return Err(SystemError::boxed(format!(
            "vault already initialized at {}",
            ctx.vault_path.display()
        )));
    }

    println!("creating new vault at {}", ctx.vault_path.display());
    let passphrase = prompt_passphrase_twice()?;

    let result = vault.initialize(&passphrase)?;
    let p = result.kdf_params;

    println!("vault initialized");
    println!("  path:       {}", ctx.vault_path.display());
    println!(
        "  kdf:        argon2id (m={} KiB, t={}, p={})",
        p.mem_kib, p.t_cost, p.p_cost
    );
    println!();
    print_mnemonic_warning(&result.mnemonic);
    audit_log::append(
        "cli.init",
        None,
        AuditResult::Ok,
        Some("vault initialized; recovery mnemonic generated".into()),
    );
    Ok(())
}
