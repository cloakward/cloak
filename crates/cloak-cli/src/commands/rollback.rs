//! Rollback-mirror maintenance commands.

use anyhow::Result;

use super::Context;

pub fn run_adopt_state(ctx: &Context, yes: bool) -> Result<()> {
    if !yes {
        anyhow::bail!(
            "refusing to adopt rollback state without --yes; review the current vault file first"
        );
    }

    let state = cloak_core::vault::Vault::adopt_current_rollback_state(&ctx.vault_path)?;
    println!("rollback state mirror adopted: counter {}", state.counter);
    println!("path: {}", ctx.vault_path.display());
    Ok(())
}
