//! `cloak init` — create a fresh vault.

use anyhow::Result;

use super::{open_vault, Context, SystemError};
use crate::prompt::prompt_passphrase_twice;

/// Initialize a new vault at `ctx.vault_path`. Refuses if one already
/// exists at that path. Prompts for the passphrase twice (or reads
/// `CLOAK_PASSPHRASE` for tests) and then prints the autotuned KDF
/// parameters so the user has a record of what their vault uses.
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
    println!("Your vault is encrypted at rest. Lose your passphrase = lose your secrets.");
    Ok(())
}
