//! `cloak status` — print vault path, KDF parameters, and lock state.

use anyhow::Result;
use cloak_core::vault::Vault;

use super::{open_vault, Context, SystemError};

/// Print a one-screen summary of the vault. If the vault is not yet
/// initialized we print "uninitialized" and return a system-level error
/// so the exit code is `2`.
pub fn run(ctx: &Context) -> Result<()> {
    let vault = open_vault(ctx)?;
    if !vault.is_initialized()? {
        println!("path:           {}", ctx.vault_path.display());
        println!("status:         uninitialized");
        return Err(SystemError::boxed("vault uninitialized"));
    }

    let s: cloak_core::vault::VaultStatus = Vault::status(&vault)?;
    println!("path:           {}", s.path.display());
    println!("format version: {}", s.format_version);
    println!("records:        {}", s.record_count);
    println!(
        "kdf:            argon2id (m={} KiB, t={}, p={})",
        s.kdf_params.mem_kib, s.kdf_params.t_cost, s.kdf_params.p_cost
    );
    println!(
        "state:          {}",
        if s.locked { "locked" } else { "unlocked" }
    );
    Ok(())
}
