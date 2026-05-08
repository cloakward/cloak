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
/// Returns the exit code as a `u8` so the dispatcher can decide
/// whether to short-circuit auto-wizard chains. `0` means success,
/// `2` means we refused to print the recovery seed (vault still
/// initialized).
pub fn run(ctx: &Context) -> Result<u8> {
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
    // The vault is on disk regardless of whether we manage to surface
    // the seed; the audit entry should reflect that. Print first, then
    // log, then propagate a non-zero exit if the printer refused.
    let printed = print_mnemonic_warning(&result.mnemonic);
    audit_log::append(
        "cli.init",
        None,
        AuditResult::Ok,
        Some("vault initialized; recovery mnemonic generated".into()),
    );
    Ok(if printed { 0 } else { 2 })
}
