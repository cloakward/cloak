//! BIP-39 recovery seed.
//!
//! At vault-creation time we generate 256 bits of entropy, encode it as a
//! 24-word English BIP-39 mnemonic, and derive a 32-byte "recovery key"
//! from the standard BIP-39 seed (PBKDF2-HMAC-SHA512, 2048 iterations,
//! salt = "mnemonic" + empty BIP-39 passphrase, 64-byte output — we use
//! the first 32 bytes). The recovery key wraps the master key under the
//! same XChaCha20-Poly1305 AEAD that the passphrase wrap uses, with a
//! distinct AAD ([`RECOVERY_AAD`]).
//!
//! This gives the user a second, offline path to the master key: if they
//! lose their passphrase but still have the 24 words written down, they
//! can run `cloak restore`, re-derive the master, and re-wrap it under a
//! freshly chosen passphrase.
//!
//! ## Invariants
//!
//! - The recovery key is **never** stored on disk. Only the wrapped
//!   master key (a fresh AEAD ciphertext + nonce) lives in the `meta`
//!   table.
//! - The mnemonic itself is shown to the user exactly once at vault
//!   creation, and on demand via `cloak backup mnemonic` (Touch ID gated,
//!   audit-logged). It is never persisted.
//! - We do **not** roll our own KDF. The seed comes from `bip39::Mnemonic::to_seed`
//!   which is the standard PBKDF2-HMAC-SHA512 construction.

use std::str::FromStr;

use bip39::{Language, Mnemonic};
use zeroize::Zeroize;

use crate::crypto::{aead, Secret};
use crate::error::{Error, Result};

/// Stable identifier written to `meta.recovery_format` for the BIP-39
/// 24-word English wrap. Bumping this lets us add v2 schemes (hardware
/// tokens, Shamir, etc.) later without ambiguity.
pub const FORMAT_BIP39_V1: &str = "bip39-v1";

/// AAD tag for the recovery-key wrap of the master key. Distinct from
/// the passphrase-wrap AAD ([`crate::vault::MASTER_AAD`]) so a wrap can
/// never be confused for the other.
pub const RECOVERY_AAD: &[u8] = b"cloak.recovery.v1";

/// Number of words in the canonical Cloak mnemonic. 24 ↔ 256 bits of
/// entropy at the BIP-39 standard rate.
pub const WORD_COUNT: usize = 24;

/// 256-bit entropy backing a 24-word English BIP-39 mnemonic.
const ENTROPY_BYTES: usize = 32;

// ----------------------------------------------------------------------
// RecoveryMnemonic
// ----------------------------------------------------------------------

/// A 24-word BIP-39 English mnemonic. Holds the words in a [`Secret<String>`]
/// so the buffer zeroizes on drop.
#[derive(Debug)]
pub struct RecoveryMnemonic(Secret<String>);

impl RecoveryMnemonic {
    /// Generate a fresh 24-word mnemonic using libsodium's CSPRNG for
    /// entropy. This is the only entropy source in the secret-protection
    /// path; we never delegate to `rand::thread_rng()`.
    pub fn generate() -> Result<Self> {
        let mut entropy_v = aead::random_bytes(ENTROPY_BYTES)?;
        let m = Mnemonic::from_entropy_in(Language::English, &entropy_v)
            .map_err(|_| Error::Other("bip39: entropy encoding failed"))?;
        // Wipe the intermediate entropy buffer.
        entropy_v.zeroize();
        Ok(Self(Secret::new(m.to_string())))
    }

    /// Parse a user-supplied mnemonic string. Trims surrounding
    /// whitespace, collapses inner whitespace runs, and validates against
    /// the English wordlist + BIP-39 checksum.
    ///
    /// On any malformed input — wrong word count, unknown word, bad
    /// checksum — returns [`Error::InvalidMnemonic`] with a stable
    /// short message (no echo of the user's input).
    pub fn parse(s: &str) -> Result<Self> {
        // Normalize: collapse all whitespace runs to single spaces and
        // lowercase. BIP-39 is case-insensitive on input but the
        // canonical representation is lowercase.
        let normalized: String = s
            .split_whitespace()
            .map(|w| w.to_lowercase())
            .collect::<Vec<_>>()
            .join(" ");
        let m = Mnemonic::from_str(&normalized).map_err(|_| Error::InvalidMnemonic)?;
        if m.word_count() != WORD_COUNT {
            return Err(Error::InvalidMnemonic);
        }
        if m.language() != Language::English {
            return Err(Error::InvalidMnemonic);
        }
        Ok(Self(Secret::new(m.to_string())))
    }

    /// Borrow the canonical word string. Caller must treat this as a
    /// secret; do not log it.
    pub fn as_phrase(&self) -> &str {
        self.0.expose_secret()
    }

    /// Render the mnemonic as `Vec<String>` of 24 words for display.
    /// Caller is responsible for zeroizing.
    pub fn words(&self) -> Vec<String> {
        self.0
            .expose_secret()
            .split_whitespace()
            .map(|w| w.to_string())
            .collect()
    }

    /// Derive the 32-byte recovery key from the mnemonic. Internally
    /// runs BIP-39's PBKDF2-HMAC-SHA512 (2048 iterations, salt prefix
    /// "mnemonic", empty BIP-39 passphrase) and uses the first 32 bytes
    /// of the resulting 64-byte seed.
    pub fn derive_recovery_key(&self) -> Result<Secret<[u8; 32]>> {
        let m = Mnemonic::from_str(self.0.expose_secret())
            .map_err(|_| Error::Other("bip39: round-trip parse failed"))?;
        // Empty passphrase per design; the user's passphrase is *separate*
        // from the BIP-39 passphrase and lives only in the passphrase-wrap.
        let seed = m.to_seed("");
        let mut key = [0u8; 32];
        key.copy_from_slice(&seed[..32]);
        Ok(Secret::new(key))
    }
}

// ----------------------------------------------------------------------
// Wrap / unwrap helpers
// ----------------------------------------------------------------------

/// Wrap a 32-byte master key under the recovery key. Returns
/// `(nonce, ciphertext)` ready to store in `meta.recovery_wrap_*`.
pub fn wrap_master(
    recovery_key: &Secret<[u8; 32]>,
    master: &[u8; 32],
) -> Result<([u8; 24], Vec<u8>)> {
    let nonce = aead::random_nonce()?;
    let ct = aead::seal(recovery_key.expose_secret(), &nonce, RECOVERY_AAD, master)?;
    Ok((nonce, ct))
}

/// Unwrap a master key from the recovery wrap. AEAD failure (wrong
/// mnemonic, tampered blob) returns [`Error::InvalidMnemonic`] rather
/// than a generic AEAD error, so the CLI can give the user a clearer
/// message.
pub fn unwrap_master(
    recovery_key: &Secret<[u8; 32]>,
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Result<Secret<[u8; 32]>> {
    let pt = aead::open(
        recovery_key.expose_secret(),
        nonce,
        RECOVERY_AAD,
        ciphertext,
    )
    .map_err(|_| Error::InvalidMnemonic)?;
    if pt.len() != 32 {
        return Err(Error::VaultFormat("recovery-wrapped master wrong length"));
    }
    let mut m = [0u8; 32];
    m.copy_from_slice(&pt);
    let mut zv = pt;
    zv.zeroize();
    Ok(Secret::new(m))
}

// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_yields_24_english_words() {
        let m = RecoveryMnemonic::generate().unwrap();
        let ws = m.words();
        assert_eq!(ws.len(), WORD_COUNT);
        for w in &ws {
            // English wordlist is all-ASCII-lowercase.
            assert!(w.chars().all(|c| c.is_ascii_lowercase()));
        }
    }

    #[test]
    fn round_trip_parse() {
        let m = RecoveryMnemonic::generate().unwrap();
        let phrase = m.as_phrase().to_string();
        let parsed = RecoveryMnemonic::parse(&phrase).unwrap();
        assert_eq!(parsed.as_phrase(), phrase);
    }

    #[test]
    fn parse_normalizes_whitespace_and_case() {
        let m = RecoveryMnemonic::generate().unwrap();
        let phrase = m.as_phrase().to_string();
        // Mangle whitespace + case but keep words.
        let mangled = format!("  {}  ", phrase.to_uppercase().replace(' ', "   \t  "));
        let parsed = RecoveryMnemonic::parse(&mangled).unwrap();
        assert_eq!(parsed.as_phrase(), phrase);
    }

    #[test]
    fn parse_rejects_bad_checksum() {
        // Take a valid mnemonic and replace the last word with another
        // wordlist entry that almost certainly fails the checksum.
        let m = RecoveryMnemonic::generate().unwrap();
        let mut ws = m.words();
        let last = ws.pop().unwrap();
        // Pick a different wordlist word to flip the checksum.
        let replacement = if last == "abandon" {
            "ability"
        } else {
            "abandon"
        };
        ws.push(replacement.to_string());
        let bad = ws.join(" ");
        let r = RecoveryMnemonic::parse(&bad);
        assert!(matches!(r, Err(Error::InvalidMnemonic)));
    }

    #[test]
    fn parse_rejects_unknown_word() {
        let m = RecoveryMnemonic::generate().unwrap();
        let mut ws = m.words();
        ws[0] = "thisisnotaword".to_string();
        let bad = ws.join(" ");
        let r = RecoveryMnemonic::parse(&bad);
        assert!(matches!(r, Err(Error::InvalidMnemonic)));
    }

    #[test]
    fn parse_rejects_wrong_word_count() {
        // 12 words are valid BIP-39 but not what Cloak issues.
        let twelve = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon about";
        let r = RecoveryMnemonic::parse(twelve);
        assert!(matches!(r, Err(Error::InvalidMnemonic)));
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let m = RecoveryMnemonic::generate().unwrap();
        let key = m.derive_recovery_key().unwrap();
        let master = [0xA5u8; 32];
        let (nonce, ct) = wrap_master(&key, &master).unwrap();
        let got = unwrap_master(&key, &nonce, &ct).unwrap();
        assert_eq!(got.expose_secret(), &master);
    }

    #[test]
    fn unwrap_with_wrong_mnemonic_returns_invalid_mnemonic() {
        let m1 = RecoveryMnemonic::generate().unwrap();
        let m2 = RecoveryMnemonic::generate().unwrap();
        let k1 = m1.derive_recovery_key().unwrap();
        let k2 = m2.derive_recovery_key().unwrap();
        let master = [0x42u8; 32];
        let (nonce, ct) = wrap_master(&k1, &master).unwrap();
        let r = unwrap_master(&k2, &nonce, &ct);
        assert!(matches!(r, Err(Error::InvalidMnemonic)));
    }

    #[test]
    fn deterministic_seed_for_known_mnemonic() {
        // BIP-39 test vector (24-word, "abandon..."): we just check that
        // the same input phrase always gives the same recovery key.
        let phrase = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon art";
        let a = RecoveryMnemonic::parse(phrase).unwrap();
        let b = RecoveryMnemonic::parse(phrase).unwrap();
        let ka = a.derive_recovery_key().unwrap();
        let kb = b.derive_recovery_key().unwrap();
        assert_eq!(ka.expose_secret(), kb.expose_secret());
    }
}
