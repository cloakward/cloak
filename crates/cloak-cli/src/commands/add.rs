//! `cloak add NAME [--kind KIND] [--tag TAG ...]` — insert a new secret.

use anyhow::Result;
use cloak_core::crypto::Secret;
use cloak_core::vault::SecretKind;
use cloak_core::Error;

use super::{open_vault, unlock::unlock_interactive, Context};

/// Add a new secret. Vault must be initialized. Prompts for the value
/// itself with echo OFF (`rpassword`) so it never appears on screen.
pub fn run(ctx: &Context, name: &str, kind: SecretKind, tags: Vec<String>) -> Result<()> {
    let mut vault = open_vault(ctx)?;
    unlock_interactive(&mut vault)?;

    // Read the secret value with echo off. We bypass the test-only
    // CLOAK_PASSPHRASE override here because that variable is for the
    // *vault* passphrase, not for secret values; if a test wants to
    // populate a secret value it should pipe it on stdin.
    let raw_value = if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        // Allow reading the value from stdin (useful for tests / pipes).
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
        // Strip exactly one trailing newline for ergonomic
        // shell-pipeline use.
        if buf.ends_with('\n') {
            buf.pop();
            if buf.ends_with('\r') {
                buf.pop();
            }
        }
        buf
    } else {
        rpassword::prompt_password("value: ")?
    };
    let value: Secret<String> = Secret::new(raw_value);

    match vault.add(name, kind, tags, &value) {
        Ok(()) => {
            println!("added: {name}");
            Ok(())
        }
        Err(Error::SecretExists(_)) => {
            anyhow::bail!("secret already exists: {name}");
        }
        Err(other) => Err(other.into()),
    }
}
