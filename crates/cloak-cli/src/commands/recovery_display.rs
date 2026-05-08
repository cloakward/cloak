//! Helpers for printing the BIP-39 recovery mnemonic to the terminal.
//!
//! Centralized so the wording is consistent across `cloak init`,
//! `cloak setup`, and `cloak backup mnemonic`.
//!
//! ## TTY safety
//!
//! The 24-word seed is the irrecoverable backstop for the vault. If it
//! lands in a log file (`cloak init > install.log`) the user has just
//! written the master secret to disk in plaintext — we cannot retract
//! it. So we refuse to write the words to a non-terminal stdout.
//!
//! Order of preference:
//!   1. stdout is a TTY -> print there as before.
//!   2. stdout is redirected -> try to open `/dev/tty` and print there.
//!      In a real interactive shell the controlling terminal is still
//!      reachable even when stdout points at a file.
//!   3. `/dev/tty` is unavailable (containers, CI, daemons) -> refuse
//!      with a stderr message and exit code 2.
//!
//! `CLOAK_ALLOW_MNEMONIC_STDOUT=1` bypasses the check. It exists for
//! the integration tests in `tests/cli.rs`, which exec the binary
//! through `assert_cmd` (no PTY). Documented as test-only in the
//! refusal message so a real user does not lean on it.

use std::fs::OpenOptions;
use std::io::{self, IsTerminal, Write};

use cloak_core::recovery::RecoveryMnemonic;

/// Env var that lets the CLI integration tests (and other no-TTY
/// harnesses) bypass the stdout-is-a-terminal check. Test-only.
const ALLOW_STDOUT_ENV: &str = "CLOAK_ALLOW_MNEMONIC_STDOUT";

/// Print the 24-word recovery mnemonic with a "WRITE THIS DOWN" banner.
///
/// Returns `true` if the words were displayed (whether to stdout or
/// `/dev/tty`), `false` if we refused because no terminal was
/// reachable. The caller is expected to translate `false` into a
/// non-zero exit; the audit-log entry stays the caller's responsibility.
#[must_use = "if the mnemonic could not be displayed the caller must surface a non-zero exit"]
pub fn print_mnemonic_warning(mnemonic: &RecoveryMnemonic) -> bool {
    let words = mnemonic.words();

    // 1. Test/CI escape hatch, or stdout already attached to a TTY.
    let allow_stdout = std::env::var_os(ALLOW_STDOUT_ENV).is_some_and(|v| v == "1" || v == "true");
    if allow_stdout || io::stdout().is_terminal() {
        let mut out = io::stdout().lock();
        let _ = write_mnemonic(&mut out, &words);
        return true;
    }

    // 2. stdout is redirected -> try the controlling terminal directly.
    //    On Linux containers without a controlling tty this opens with
    //    ENXIO; on macOS it succeeds for any interactive shell session.
    if let Ok(mut tty) = OpenOptions::new().write(true).open("/dev/tty") {
        if write_mnemonic(&mut tty, &words).is_ok() {
            // Tell the user via stderr that the words went to the tty
            // and not to wherever stdout was redirected. Otherwise a
            // user piping `cloak init | tee` is left wondering.
            let _ = writeln!(
                io::stderr(),
                "(recovery seed written to /dev/tty, not to stdout)"
            );
            return true;
        }
    }

    // 3. No terminal reachable. Refuse loudly on stderr.
    let _ = writeln!(
        io::stderr(),
        "refusing to print recovery seed: stdout is not a terminal and \
         /dev/tty is unavailable. Set {ALLOW_STDOUT_ENV}=1 to override \
         (test-only; do NOT use in production)."
    );
    false
}

/// Render the banner + word grid + footer to an arbitrary writer.
/// Factored out so we can target either stdout or `/dev/tty` without
/// duplicating the layout.
fn write_mnemonic<W: Write>(w: &mut W, words: &[String]) -> io::Result<()> {
    writeln!(
        w,
        "--------------------------------------------------------------------"
    )?;
    writeln!(
        w,
        "RECOVERY SEED — WRITE THESE 24 WORDS DOWN ON PAPER. STORE OFFLINE."
    )?;
    writeln!(
        w,
        "--------------------------------------------------------------------"
    )?;
    writeln!(w)?;
    write_word_grid(w, words)?;
    writeln!(w)?;
    writeln!(
        w,
        "If you lose your passphrase, these words are the ONLY way back into"
    )?;
    writeln!(
        w,
        "your vault. Cloak does NOT keep a copy. Anyone who reads them can"
    )?;
    writeln!(
        w,
        "decrypt every secret in the vault — treat them like the passphrase."
    )?;
    writeln!(w)?;
    writeln!(w, "Verify you wrote them down correctly with:")?;
    writeln!(w, "    cloak backup verify")?;
    writeln!(
        w,
        "--------------------------------------------------------------------"
    )?;
    Ok(())
}

/// Write a 6-row x 4-column numbered grid of words to `w`. Output is
/// plain ASCII so it copies cleanly into a notes app or pastes into a
/// paper printout.
fn write_word_grid<W: Write>(w: &mut W, words: &[String]) -> io::Result<()> {
    // 4 columns, 6 rows. Each cell is "NN. word" padded to a fixed
    // width. 24 word English BIP-39 entries are at most 8 chars long,
    // which means a 14-char column comfortably fits.
    const COLS: usize = 4;
    const COL_WIDTH: usize = 14;
    let rows = words.len().div_ceil(COLS);
    for row in 0..rows {
        for col in 0..COLS {
            let idx = col * rows + row;
            if idx >= words.len() {
                continue;
            }
            let cell = format!("{:>2}. {}", idx + 1, words[idx]);
            write!(w, "  {cell:<COL_WIDTH$}")?;
        }
        writeln!(w)?;
    }
    Ok(())
}
