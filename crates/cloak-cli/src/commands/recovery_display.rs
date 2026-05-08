//! Helpers for printing the BIP-39 recovery mnemonic to the terminal.
//!
//! Centralized so the wording is consistent across `cloak init`,
//! `cloak setup`, and `cloak backup mnemonic`.

use cloak_core::recovery::RecoveryMnemonic;

/// Print the 24 words in a 4 x 6 numbered grid plus a heavy-handed
/// "WRITE THIS DOWN" banner. We intentionally write to stdout (not
/// stderr) so a user piping `cloak init` to a file gets the words; the
/// banner is hard to miss and the words are the value.
pub fn print_mnemonic_warning(mnemonic: &RecoveryMnemonic) {
    let words = mnemonic.words();
    println!("--------------------------------------------------------------------");
    println!("RECOVERY SEED — WRITE THESE 24 WORDS DOWN ON PAPER. STORE OFFLINE.");
    println!("--------------------------------------------------------------------");
    println!();
    print_word_grid(&words);
    println!();
    println!("If you lose your passphrase, these words are the ONLY way back into");
    println!("your vault. Cloak does NOT keep a copy. Anyone who reads them can");
    println!("decrypt every secret in the vault — treat them like the passphrase.");
    println!();
    println!("Verify you wrote them down correctly with:");
    println!("    cloak backup verify");
    println!("--------------------------------------------------------------------");
}

/// Print a 6-row x 4-column numbered grid of words. Output is plain
/// ASCII so it copies cleanly into a notes app or pastes into a paper
/// printout.
pub fn print_word_grid(words: &[String]) {
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
            print!("  {cell:<COL_WIDTH$}");
        }
        println!();
    }
}
