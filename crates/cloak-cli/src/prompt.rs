//! Interactive prompts (passphrase / yes-no) with zeroize-on-drop buffers.
//!
//! The CLI is the only place in the workspace that reads a passphrase from
//! a human, so the discipline lives here:
//!
//! - All passphrase entry uses `rpassword::prompt_password` (no echo).
//! - Buffers are wrapped in [`Secret<String>`] so they zeroize on drop.
//! - Passphrase confirmation is compared in constant time via
//!   [`subtle::ConstantTimeEq`] before being returned.
//! - A hidden `CLOAK_PASSPHRASE` env override exists for integration tests
//!   (and emits a stderr warning if used outside of `cargo test`).

use anyhow::{Context, Result};
use cloak_core::crypto::Secret;
use std::io::{self, IsTerminal, Write};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Env var that, if set, replaces all interactive passphrase prompts with
/// its value. Intended for `assert_cmd` integration tests; we still warn on
/// stderr when set in a TTY context so it's not silently honored in
/// production.
const TEST_PASSPHRASE_ENV: &str = "CLOAK_PASSPHRASE";

/// Read a passphrase from stdin without echo. Honors `CLOAK_PASSPHRASE` if
/// set (test-only escape hatch — emits a stderr warning when stdout is a
/// TTY because that's almost certainly a misconfiguration).
pub fn prompt_passphrase(label: &str) -> Result<Secret<String>> {
    if let Ok(p) = std::env::var(TEST_PASSPHRASE_ENV) {
        if io::stdout().is_terminal() {
            eprintln!(
                "warning: CLOAK_PASSPHRASE is set; using it instead of prompting (test-only)"
            );
        }
        return Ok(Secret::new(p));
    }
    let raw = rpassword::prompt_password(label).context("failed to read passphrase")?;
    Ok(Secret::new(raw))
}

/// Prompt twice, retrying up to 3 times if the values don't match.
///
/// Comparison is in constant time so that an attacker observing a side
/// channel (timing on a noisy terminal) cannot learn anything about which
/// prefix matched.
pub fn prompt_passphrase_twice() -> Result<Secret<String>> {
    // Honor the test override exactly once: skip confirmation entirely.
    if let Ok(p) = std::env::var(TEST_PASSPHRASE_ENV) {
        if io::stdout().is_terminal() {
            eprintln!(
                "warning: CLOAK_PASSPHRASE is set; using it instead of prompting (test-only)"
            );
        }
        return Ok(Secret::new(p));
    }

    for attempt in 0..3u32 {
        let first =
            rpassword::prompt_password("new passphrase: ").context("failed to read passphrase")?;
        let mut second = rpassword::prompt_password("confirm passphrase: ")
            .context("failed to read passphrase confirmation")?;

        let matches: bool = first.as_bytes().ct_eq(second.as_bytes()).into();
        // Wipe the second buffer immediately whether or not it matched —
        // we never need it again.
        second.zeroize();

        if matches {
            return Ok(Secret::new(first));
        }

        // Wipe the first buffer too before looping.
        let mut first = first;
        first.zeroize();

        if attempt + 1 == 3 {
            anyhow::bail!("passphrases did not match after 3 attempts");
        }
        eprintln!("passphrases did not match, try again");
    }
    unreachable!("loop returns or bails")
}

/// Prompt for a yes/no answer on stdin. `default_yes` controls which
/// answer is returned on empty input. Anything starting with `y/Y` is yes,
/// anything starting with `n/N` is no, anything else re-prompts (up to 3
/// times before giving up and using the default).
pub fn prompt_yes_no(label: &str, default_yes: bool) -> Result<bool> {
    let suffix = if default_yes { " [Y/n] " } else { " [y/N] " };
    for _ in 0..3 {
        eprint!("{label}{suffix}");
        io::stderr().flush().ok();

        let mut buf = String::new();
        io::stdin()
            .read_line(&mut buf)
            .context("failed to read confirmation")?;
        let trimmed = buf.trim();
        if trimmed.is_empty() {
            return Ok(default_yes);
        }
        match trimmed.chars().next().map(|c| c.to_ascii_lowercase()) {
            Some('y') => return Ok(true),
            Some('n') => return Ok(false),
            _ => continue,
        }
    }
    Ok(default_yes)
}
