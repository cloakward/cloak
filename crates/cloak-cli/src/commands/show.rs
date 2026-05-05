//! `cloak show NAME [--allow-redirect] [--newline]` — reveal plaintext.
//!
//! This is the *only* place in the CLI that prints secret material. The
//! discipline here is heavy:
//!
//! 1. Refuse non-TTY stdout unless the user opts in with
//!    `--allow-redirect` (so secrets don't end up in shell history /
//!    redirected pipes by accident).
//! 2. Unlock the vault (passphrase prompt with up to 3 retries).
//! 3. Require Touch ID confirmation on macOS unless `--no-biometric` is
//!    set globally; on non-macOS the [`crate::biometric_macos`] stub
//!    short-circuits to `Ok(true)`.
//! 4. Decrypt, write the plaintext bytes, then explicitly drop the
//!    `Secret<String>` so its zeroize-on-drop runs immediately.

use std::io::{IsTerminal, Write};

use anyhow::Result;
use cloak_core::Error;

use super::{open_vault, unlock::unlock_interactive, Context};
use crate::biometric_macos;

/// Reveal a single secret's plaintext.
pub fn run(ctx: &Context, name: &str, allow_redirect: bool, newline: bool) -> Result<()> {
    // 1. TTY guard.
    if !std::io::stdout().is_terminal() && !allow_redirect {
        eprintln!("refusing to write secret to non-TTY (use --allow-redirect)");
        anyhow::bail!("non-TTY output without --allow-redirect");
    }

    let mut vault = open_vault(ctx)?;

    // 2. Unlock with the passphrase.
    unlock_interactive(&mut vault)?;

    // 3. Biometric step. Off only when --no-biometric is passed; the
    //    non-macOS stub returns true unconditionally so this is a noop
    //    on Linux/Windows for now.
    if !ctx.no_biometric {
        let reason = format!("Reveal secret '{name}' from Cloak vault");
        match biometric_macos::authenticate(&reason) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!("biometric authentication failed");
                anyhow::bail!("biometric authentication failed");
            }
            Err(e) => {
                eprintln!("biometric authentication failed: {e}");
                anyhow::bail!("biometric authentication failed");
            }
        }
    }

    // 4. Decrypt + write. We hold the `Secret<String>` for the
    //    shortest possible window: write, flush, drop.
    let plaintext = match vault.show(name) {
        Ok(s) => s,
        Err(Error::SecretNotFound(_)) => anyhow::bail!("secret not found: {name}"),
        Err(other) => return Err(other.into()),
    };
    {
        let mut out = std::io::stdout().lock();
        out.write_all(plaintext.expose_secret().as_bytes())?;
        if newline {
            out.write_all(b"\n")?;
        }
        out.flush()?;
    }
    // Explicitly drop now so the zeroize-on-drop happens at a known
    // point rather than at end-of-scope.
    drop(plaintext);
    Ok(())
}
