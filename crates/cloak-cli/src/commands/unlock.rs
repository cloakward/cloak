//! Shared unlock helper used by every mutating subcommand.
//!
//! Implements the "ask for the passphrase, retry up to 3 times on
//! [`Error::InvalidPassphrase`]" interaction. Other error variants from
//! [`Vault::unlock`] are not retried — they indicate a real problem
//! (corrupted header, unsupported version, etc.).

use anyhow::Result;
use cloak_core::vault::Vault;
use cloak_core::Error;

use crate::prompt::prompt_passphrase;

use super::SystemError;

/// Maximum number of passphrase attempts before we give up.
pub const MAX_ATTEMPTS: u32 = 3;

/// Unlock the vault interactively. Refuses early if the vault has not
/// been initialized (a `cloak init`-shaped problem the caller should fix
/// first).
pub fn unlock_interactive(vault: &mut Vault) -> Result<()> {
    if !vault.is_initialized()? {
        return Err(SystemError::boxed(
            "vault not initialized — run `cloak init` first",
        ));
    }

    for attempt in 1..=MAX_ATTEMPTS {
        let pass = prompt_passphrase("passphrase: ")?;
        match vault.unlock(&pass) {
            Ok(()) => return Ok(()),
            Err(Error::InvalidPassphrase) => {
                if attempt == MAX_ATTEMPTS {
                    anyhow::bail!("invalid passphrase (giving up after {MAX_ATTEMPTS} attempts)");
                }
                eprintln!("invalid passphrase, try again");
            }
            Err(other) => return Err(other.into()),
        }
    }
    unreachable!("loop returns or bails")
}
