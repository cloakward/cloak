//! `cloak rm NAME [--yes]` — delete a secret.

use anyhow::Result;
use cloak_core::Error;

use super::{open_vault, unlock::unlock_interactive, Context};
use crate::prompt::prompt_yes_no;

/// Remove a secret. Asks for confirmation unless `--yes` is set.
///
/// We unlock the vault before deleting even though `Vault::rm` does not
/// strictly require it; this preserves the invariant that any
/// state-mutating CLI action requires the user to authenticate, which is
/// what `BUILD_PLAN.md` §2 calls for.
pub fn run(ctx: &Context, name: &str, yes: bool) -> Result<()> {
    let mut vault = open_vault(ctx)?;

    // Refuse early if the name doesn't exist — friendlier than asking
    // the user to confirm and then erroring.
    match vault.get_metadata(name) {
        Ok(_) => {}
        Err(Error::SecretNotFound(_)) => anyhow::bail!("secret not found: {name}"),
        Err(other) => return Err(other.into()),
    }

    if !yes {
        let confirmed = prompt_yes_no(&format!("delete secret '{name}'?"), false)?;
        if !confirmed {
            println!("cancelled");
            return Ok(());
        }
    }

    unlock_interactive(&mut vault)?;
    vault.rm(name)?;
    println!("removed: {name}");
    Ok(())
}
