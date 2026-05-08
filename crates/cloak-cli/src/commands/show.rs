//! `cloak show NAME [--allow-redirect] [--newline]` — reveal plaintext.
//!
//! This is the *only* place in the CLI that prints secret material. The
//! discipline here is heavy:
//!
//! 1. Refuse non-TTY stdout unless the user opts in with
//!    `--allow-redirect` (so secrets don't end up in shell history /
//!    redirected pipes by accident).
//! 2. Unlock the vault (passphrase prompt with up to 3 retries).
//! 3. Require Touch ID confirmation on macOS / polkit confirmation on
//!    Linux (action `dev.cloak.show-secret`) unless `--no-biometric` is
//!    set globally; see [`cloak_core::biometric`]. The daemon's own
//!    `vault.show` handler runs the same gate server-side so a
//!    same-UID attacker who skips the CLI cannot skip the prompt.
//! 4. Decrypt, write the plaintext bytes, then explicitly drop the
//!    `Secret<String>` so its zeroize-on-drop runs immediately.

use std::io::{IsTerminal, Write};

use anyhow::Result;
use cloak_core::Error;

use cloak_core::biometric;

use super::{open_vault, unlock::unlock_interactive, Context};

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

    // 3. Biometric / user-presence step. Off only when --no-biometric
    //    is passed. On macOS this is Touch ID; on Linux it's a polkit
    //    confirmation against the `dev.cloak.show-secret` action. On
    //    other targets the gate fails closed. The same gate lives in
    //    `cloakd`'s `vault.show` handler — a same-UID attacker who
    //    bypasses this CLI by talking to the daemon socket directly
    //    still has to face the prompt server-side.
    if !ctx.no_biometric {
        let reason = format!("Reveal secret '{name}' from Cloak vault");
        match biometric::authenticate(&reason) {
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
