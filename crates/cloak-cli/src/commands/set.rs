//! `cloak set NAME` — update an existing secret's value.

use anyhow::Result;
use cloak_core::crypto::Secret;
use cloak_core::Error;

use super::{open_vault, unlock::unlock_interactive, Context};

/// Update the value of an existing secret.
pub fn run(ctx: &Context, name: &str) -> Result<()> {
    let mut vault = open_vault(ctx)?;
    unlock_interactive(&mut vault)?;

    let raw_value = if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
        if buf.ends_with('\n') {
            buf.pop();
            if buf.ends_with('\r') {
                buf.pop();
            }
        }
        buf
    } else {
        rpassword::prompt_password("new value: ")?
    };
    let value: Secret<String> = Secret::new(raw_value);

    match vault.set(name, &value) {
        Ok(()) => {
            println!("updated: {name}");
            Ok(())
        }
        Err(Error::SecretNotFound(_)) => {
            anyhow::bail!("secret not found: {name}");
        }
        Err(other) => Err(other.into()),
    }
}
