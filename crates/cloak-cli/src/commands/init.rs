//! `cloak init` — create a fresh vault.

use anyhow::Result;
use cloak_core::audit::AuditResult;

use super::audit_log;
use super::recovery_display::{preflight_mnemonic_warning, print_mnemonic_warning};
use super::{open_vault, Context, SystemError};
use crate::prompt::prompt_strong_passphrase_twice;

/// Initialize a new vault at `ctx.vault_path`. Refuses if one already
/// exists at that path. Prompts for the passphrase twice (or reads the
/// guarded test-only `CLOAK_PASSPHRASE`) and then prints the autotuned
/// KDF parameters so the user has a record of what their vault uses.
///
/// Also generates and prints a 24-word BIP-39 recovery mnemonic ONCE.
/// Cloak does not keep a copy; the user must write the words down.
/// Returns the exit code as a `u8` so the dispatcher can decide
/// whether to short-circuit auto-wizard chains. `0` means success,
/// `2` means we refused to print the recovery seed before creating the
/// vault, so no unrecoverable vault was written.
pub fn run(ctx: &Context) -> Result<u8> {
    let mut vault = open_vault(ctx)?;
    if vault.is_initialized()? {
        return Err(SystemError::boxed(format!(
            "vault already initialized at {}",
            ctx.vault_path.display()
        )));
    }

    preflight_mnemonic_warning()?;

    println!("creating new vault at {}", ctx.vault_path.display());
    let passphrase = prompt_strong_passphrase_twice()?;

    audit_log::append_required_for_initialization(
        "cli.init",
        None,
        AuditResult::Started,
        Some("vault initialization started".into()),
    )?;
    let result = match vault.initialize(&passphrase) {
        Ok(r) => r,
        Err(e) => {
            audit_log::append_required_for_initialization(
                "cli.init",
                None,
                AuditResult::Error,
                Some("vault initialization failed".into()),
            )?;
            return Err(e.into());
        }
    };
    let p = result.kdf_params;

    println!("vault initialized");
    println!("  path:       {}", ctx.vault_path.display());
    println!(
        "  kdf:        argon2id (m={} KiB, t={}, p={})",
        p.mem_kib, p.t_cost, p.p_cost
    );
    println!();
    // The vault is committed now and the mnemonic is show-once. Print it before
    // any post-commit audit append can fail; the pre-init audit entry above is
    // the fail-closed gate before mutation.
    let printed = match print_mnemonic_warning(&result.mnemonic) {
        Ok(printed) => printed,
        Err(e) => {
            let _ = audit_log::append_required_for_initialization(
                "cli.init",
                None,
                AuditResult::Error,
                Some("vault initialized but recovery mnemonic display failed".into()),
            );
            return Err(anyhow::anyhow!(
                "failed to display recovery mnemonic after vault initialization: {e}"
            ));
        }
    };
    audit_log::append_required_for_initialization(
        "cli.init",
        None,
        AuditResult::Ok,
        Some("vault initialized; recovery mnemonic generated".into()),
    )?;
    Ok(if printed { 0 } else { 2 })
}
