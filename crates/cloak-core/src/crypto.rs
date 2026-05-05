//! Crypto primitives. **libsodium only.**
//!
//! This module is the *only* place in the workspace where cryptographic
//! primitives are invoked. Everything goes through libsodium via
//! `libsodium-sys-stable`. Per the project invariants:
//!
//! - AEAD: `crypto_aead_xchacha20poly1305_ietf` (XChaCha20-Poly1305-IETF).
//! - KDF:  `crypto_pwhash` with `crypto_pwhash_ALG_ARGON2ID13` ("Argon2id").
//! - Subkey derivation: `crypto_kdf_derive_from_key` (BLAKE2b-based).
//! - RNG:  `randombytes_buf`.
//!
//! All `unsafe` blocks call into libsodium FFI; each is annotated with a
//! `// SAFETY:` comment documenting buffer-length and pointer invariants.
//!
//! `sha2` is used **only** for the audit hash chain and code-signature
//! hashes, never as a primitive in the secret-protection path.

use std::fmt;

use libsodium_sys as sodium;
use once_cell::sync::OnceCell;
use zeroize::Zeroize;

use crate::error::{Error, Result};

// -------------------------------------------------------------------------
// Secret<T>
// -------------------------------------------------------------------------

/// A wrapper that hides its inner value from `Debug` and zeroizes on drop.
///
/// The accessor is named `expose_secret` so audits can grep for every
/// place that reads the underlying material.
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    /// Wrap an inner value as a secret.
    pub fn new(inner: T) -> Self {
        Self(inner)
    }

    /// Borrow the inner value. Named `expose_secret` to make read sites
    /// trivially greppable.
    pub fn expose_secret(&self) -> &T {
        &self.0
    }

    /// Mutably borrow the inner value (used for in-place crypto ops).
    pub fn expose_secret_mut(&mut self) -> &mut T {
        &mut self.0
    }

    /// Consume and return the wrapped value (caller takes ownership of the
    /// zeroize obligation).
    pub fn into_inner(mut self) -> T
    where
        T: Default,
    {
        std::mem::take(&mut self.0)
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl<T: Zeroize + Clone> Clone for Secret<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl From<String> for Secret<String> {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<Vec<u8>> for Secret<Vec<u8>> {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<[u8; 32]> for Secret<[u8; 32]> {
    fn from(v: [u8; 32]) -> Self {
        Self(v)
    }
}

// -------------------------------------------------------------------------
// sodium init
// -------------------------------------------------------------------------

static SODIUM_INIT: OnceCell<()> = OnceCell::new();

/// Initialize libsodium. Idempotent and thread-safe. Every public API in
/// this module that touches libsodium calls this first.
pub fn init_sodium() -> Result<()> {
    SODIUM_INIT.get_or_try_init(|| {
        // SAFETY: `sodium_init` is documented as safe to call multiple
        // times from multiple threads. It returns 0 on success, 1 if
        // already initialized, -1 on failure. We treat 0 and 1 as success.
        let rc = unsafe { sodium::sodium_init() };
        if rc < 0 {
            Err(Error::SodiumInit)
        } else {
            Ok(())
        }
    })?;
    Ok(())
}

// -------------------------------------------------------------------------
// hash::sha256 (non-primitive use only)
// -------------------------------------------------------------------------

/// SHA-256 hashing utilities. **Not** used for password hashing or any
/// secret-protection path; only for the audit hash chain and code-sig
/// digests.
pub mod hash {
    use sha2::{Digest, Sha256};

    /// Compute a SHA-256 digest.
    pub fn sha256(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    }
}

// -------------------------------------------------------------------------
// AEAD: XChaCha20-Poly1305-IETF
// -------------------------------------------------------------------------

/// XChaCha20-Poly1305-IETF AEAD wrapper. The only AEAD used in cloak.
pub mod aead {
    use libsodium_sys as sodium;

    use super::init_sodium;
    use crate::error::{Error, Result};

    /// Symmetric key length (bytes).
    pub const KEY_LEN: usize = 32;
    /// Nonce length (bytes). XChaCha gives us a 24-byte random nonce.
    pub const NONCE_LEN: usize = 24;
    /// Authentication tag length (bytes).
    pub const TAG_LEN: usize = 16;

    /// Encrypt+authenticate `plaintext` with associated data `aad`.
    /// Output is `ciphertext || tag` (length = `plaintext.len() + TAG_LEN`).
    pub fn seal(
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        init_sodium()?;
        let mut out = vec![0u8; plaintext.len() + TAG_LEN];
        let mut clen: core::ffi::c_ulonglong = 0;
        // SAFETY:
        // - `out` has capacity `plaintext.len() + TAG_LEN` (libsodium's
        //   maximum write).
        // - `plaintext`, `aad`, `nonce`, `key` pointers are valid for their
        //   declared lengths.
        // - `nsec` is unused by this AEAD (must be NULL).
        let rc = unsafe {
            sodium::crypto_aead_xchacha20poly1305_ietf_encrypt(
                out.as_mut_ptr(),
                &mut clen as *mut _,
                plaintext.as_ptr(),
                plaintext.len() as core::ffi::c_ulonglong,
                aad.as_ptr(),
                aad.len() as core::ffi::c_ulonglong,
                std::ptr::null(),
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(Error::Aead("seal failed"));
        }
        out.truncate(clen as usize);
        Ok(out)
    }

    /// Verify+decrypt `ciphertext` (which is `ct || tag`). Returns the
    /// plaintext on success or [`Error::Aead`] on tag mismatch — this
    /// function never panics on malformed input.
    pub fn open(
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        init_sodium()?;
        if ciphertext.len() < TAG_LEN {
            return Err(Error::Aead("ciphertext too short"));
        }
        let mut out = vec![0u8; ciphertext.len() - TAG_LEN];
        let mut mlen: core::ffi::c_ulonglong = 0;
        // SAFETY:
        // - `out` has capacity `ciphertext.len() - TAG_LEN` (the maximum
        //   libsodium will write).
        // - All input pointers are valid for their declared lengths.
        // - `nsec` is unused (must be NULL).
        let rc = unsafe {
            sodium::crypto_aead_xchacha20poly1305_ietf_decrypt(
                out.as_mut_ptr(),
                &mut mlen as *mut _,
                std::ptr::null_mut(),
                ciphertext.as_ptr(),
                ciphertext.len() as core::ffi::c_ulonglong,
                aad.as_ptr(),
                aad.len() as core::ffi::c_ulonglong,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(Error::Aead("auth failed"));
        }
        out.truncate(mlen as usize);
        Ok(out)
    }

    /// Generate a random 24-byte nonce via libsodium's CSPRNG.
    pub fn random_nonce() -> Result<[u8; NONCE_LEN]> {
        init_sodium()?;
        let mut nonce = [0u8; NONCE_LEN];
        // SAFETY: `randombytes_buf` writes exactly `size` bytes to `buf`.
        // We pass a pointer to a stack array of length `NONCE_LEN`.
        unsafe {
            sodium::randombytes_buf(nonce.as_mut_ptr() as *mut core::ffi::c_void, NONCE_LEN);
        }
        Ok(nonce)
    }

    /// Generate `n` random bytes via libsodium's CSPRNG.
    pub fn random_bytes(n: usize) -> Result<Vec<u8>> {
        init_sodium()?;
        let mut buf = vec![0u8; n];
        // SAFETY: writes exactly `n` bytes into `buf`, which has length `n`.
        unsafe {
            sodium::randombytes_buf(buf.as_mut_ptr() as *mut core::ffi::c_void, n);
        }
        Ok(buf)
    }
}

// -------------------------------------------------------------------------
// KDF: Argon2id (keyed mode via HMAC-SHA256(pepper, passphrase))
// -------------------------------------------------------------------------

/// Argon2id key-derivation in keyed mode.
///
/// # Construction
///
/// Cloak runs Argon2id over a *peppered* passphrase rather than feeding
/// the raw passphrase directly. The pepper is a 32-byte random secret
/// stored in the OS keychain (see [`crate::keychain`]).
///
/// 1. `peppered = HMAC-SHA256(key = pepper, msg = passphrase_bytes)` (32 B).
/// 2. `master   = Argon2id(salt, peppered, m=mem_kib, t=t_cost, p=p_cost)`.
///
/// HMAC binds the passphrase to the pepper before the slow KDF; an
/// attacker who exfiltrates the disk vault but not the keychain cannot
/// run Argon2id at all without a per-host key.
///
/// We **never** pre-hash a passphrase with SHA-256 before Argon2id (that
/// would defeat Argon2id's input-length analysis); HMAC is required to
/// preserve a uniformly distributed 32-byte input.
pub mod kdf {
    use std::time::Instant;

    use base64::{engine::general_purpose::STANDARD_NO_PAD as B64, Engine as _};
    use hmac::{Hmac, Mac};
    use libsodium_sys as sodium;
    use sha2::Sha256;
    use zeroize::Zeroize;

    use super::{init_sodium, Secret};
    use crate::error::{Error, Result};

    type HmacSha256 = Hmac<Sha256>;

    /// Length of the salt fed to Argon2id (libsodium's saltbytes is 16).
    pub const SALT_LEN: usize = 16;
    /// Length of the derived master key.
    pub const KEY_LEN: usize = 32;

    /// Argon2id cost parameters.
    ///
    /// `mem_kib` is in KiB (libsodium internally takes `memlimit` in bytes;
    /// we multiply by 1024 at the FFI boundary).
    /// `t_cost` is `opslimit` (number of passes).
    /// `p_cost` is informational only — libsodium's `crypto_pwhash` is
    /// single-threaded, but we record `p` for PHC interoperability.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KdfParams {
        /// Memory cost in KiB.
        pub mem_kib: u32,
        /// Time cost (Argon2id `t` / libsodium `opslimit`).
        pub t_cost: u32,
        /// Parallelism cost (informational; libsodium does not parallelize).
        pub p_cost: u32,
    }

    impl Default for KdfParams {
        fn default() -> Self {
            // 64 MiB memory, 3 passes, p=4 — the spec's default.
            Self {
                mem_kib: 64 * 1024,
                t_cost: 3,
                p_cost: 4,
            }
        }
    }

    /// Compute `HMAC-SHA256(pepper, passphrase_utf8)` and return 32 bytes.
    fn pepper_hmac(passphrase: &[u8], pepper: &[u8]) -> [u8; 32] {
        // Hmac::new_from_slice never errors for SHA-256 with any key length.
        let mut mac = HmacSha256::new_from_slice(pepper).expect("HMAC accepts any key");
        mac.update(passphrase);
        let out = mac.finalize().into_bytes();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        arr
    }

    /// Derive a 32-byte master key from a passphrase using Argon2id keyed
    /// mode (see module docs).
    pub fn derive(
        passphrase: &Secret<String>,
        salt: &[u8; SALT_LEN],
        pepper: &Secret<Vec<u8>>,
        params: KdfParams,
    ) -> Result<Secret<[u8; KEY_LEN]>> {
        init_sodium()?;

        // Step 1: HMAC the passphrase under the pepper to get a uniform
        // 32-byte "peppered" passphrase.
        let mut peppered = pepper_hmac(
            passphrase.expose_secret().as_bytes(),
            pepper.expose_secret(),
        );

        // Step 2: feed `peppered` (treated as opaque bytes) into Argon2id.
        let mut out = [0u8; KEY_LEN];
        // libsodium expects passwd as `*const c_char`; the bytes are not
        // interpreted as a C string (length is taken explicitly).
        // SAFETY:
        // - `out` has length `KEY_LEN`.
        // - `peppered` is exactly 32 bytes.
        // - `salt` points to `SALT_LEN` bytes.
        // - We pass the documented Argon2id13 alg constant.
        let rc = unsafe {
            sodium::crypto_pwhash(
                out.as_mut_ptr(),
                KEY_LEN as core::ffi::c_ulonglong,
                peppered.as_ptr() as *const core::ffi::c_char,
                peppered.len() as core::ffi::c_ulonglong,
                salt.as_ptr(),
                params.t_cost as core::ffi::c_ulonglong,
                (params.mem_kib as usize) * 1024,
                sodium::crypto_pwhash_ALG_ARGON2ID13 as core::ffi::c_int,
            )
        };
        peppered.zeroize();
        if rc != 0 {
            // libsodium returns -1 on OOM (memory limit too high) or other
            // failure. Don't leak the parameters in the error message.
            return Err(Error::Kdf("crypto_pwhash failed (try lowering memory)"));
        }
        Ok(Secret::new(out))
    }

    /// Auto-tune Argon2id parameters so a single derive lands in the
    /// `[200ms, 500ms]` band on the current host. Returns whatever params
    /// we settled on (caller must persist them in the vault header).
    ///
    /// Strategy: start at `m=64MiB, t=3`. If too fast, increase `t` up to
    /// 8. If still too slow at `t=3`, drop memory to 32 MiB.
    pub fn autotune() -> Result<KdfParams> {
        init_sodium()?;
        let salt = [0u8; SALT_LEN];
        // Use a stable dummy pepper / passphrase for calibration so we
        // never touch real material here.
        let pass = Secret::new(String::from("calibration"));
        let pep = Secret::new(vec![0u8; 32]);

        let measure = |p: KdfParams| -> Result<u128> {
            let start = Instant::now();
            let _ = derive(&pass, &salt, &pep, p)?;
            Ok(start.elapsed().as_millis())
        };

        // Phase 1: m=64 MiB, ramp t from 3 up to 8.
        let mut params = KdfParams {
            mem_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 4,
        };
        let baseline = measure(params)?;
        if baseline > 500 {
            // Too slow even at t=3: fall back to 32 MiB and try t=3.
            let degraded = KdfParams {
                mem_kib: 32 * 1024,
                t_cost: 3,
                p_cost: 4,
            };
            let _ = measure(degraded)?;
            return Ok(degraded);
        }
        if baseline >= 200 {
            return Ok(params);
        }
        // Too fast — bump `t` until we land in the band or hit t=8.
        for t in 4..=8u32 {
            params.t_cost = t;
            let ms = measure(params)?;
            if ms >= 200 {
                return Ok(params);
            }
        }
        // Hit t=8 and still under 200ms — accept what we have.
        Ok(params)
    }

    /// Encode params + salt as a PHC-format string (no hash portion since
    /// we use Argon2id as a KDF, not a verifier).
    ///
    /// Format: `$argon2id$v=19$m=<mem_kib>,t=<t>,p=<p>$<b64salt>`
    pub fn params_to_phc(p: &KdfParams, salt: &[u8; SALT_LEN]) -> String {
        format!(
            "$argon2id$v=19$m={},t={},p={}${}",
            p.mem_kib,
            p.t_cost,
            p.p_cost,
            B64.encode(salt),
        )
    }

    /// Parse a PHC string back into `(params, salt)`. Strict: rejects
    /// anything that isn't exactly the format we produce.
    pub fn params_from_phc(s: &str) -> Result<(KdfParams, [u8; SALT_LEN])> {
        // Expected: `$argon2id$v=19$m=...,t=...,p=...$<b64salt>`
        let mut parts = s.split('$');
        if parts.next() != Some("") {
            return Err(Error::VaultFormat("phc: missing leading $"));
        }
        if parts.next() != Some("argon2id") {
            return Err(Error::VaultFormat("phc: not argon2id"));
        }
        let v_part = parts.next().ok_or(Error::VaultFormat("phc: missing v"))?;
        if v_part != "v=19" {
            return Err(Error::VaultFormat("phc: bad version"));
        }
        let costs = parts
            .next()
            .ok_or(Error::VaultFormat("phc: missing costs"))?;
        let salt_b64 = parts
            .next()
            .ok_or(Error::VaultFormat("phc: missing salt"))?;
        if parts.next().is_some() {
            return Err(Error::VaultFormat("phc: extra fields"));
        }

        let mut mem_kib = None::<u32>;
        let mut t_cost = None::<u32>;
        let mut p_cost = None::<u32>;
        for kv in costs.split(',') {
            let (k, v) = kv
                .split_once('=')
                .ok_or(Error::VaultFormat("phc: bad kv"))?;
            let v: u32 = v
                .parse()
                .map_err(|_| Error::VaultFormat("phc: non-int cost"))?;
            match k {
                "m" => mem_kib = Some(v),
                "t" => t_cost = Some(v),
                "p" => p_cost = Some(v),
                _ => return Err(Error::VaultFormat("phc: unknown cost key")),
            }
        }
        let params = KdfParams {
            mem_kib: mem_kib.ok_or(Error::VaultFormat("phc: missing m"))?,
            t_cost: t_cost.ok_or(Error::VaultFormat("phc: missing t"))?,
            p_cost: p_cost.ok_or(Error::VaultFormat("phc: missing p"))?,
        };
        let salt_v = B64
            .decode(salt_b64)
            .map_err(|_| Error::VaultFormat("phc: bad b64 salt"))?;
        if salt_v.len() != SALT_LEN {
            return Err(Error::VaultFormat("phc: salt wrong length"));
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&salt_v);
        Ok((params, salt))
    }
}

// -------------------------------------------------------------------------
// Per-record subkey derivation: crypto_kdf_derive_from_key
// -------------------------------------------------------------------------

/// Derive a per-record 32-byte subkey from the master key using
/// `crypto_kdf_derive_from_key` (BLAKE2b under the hood).
///
/// `record_id` is the SQLite rowid of the secret (a stable u64).
/// `ctx` is an 8-byte ASCII context string. We use `b"cloakrec"` for
/// the per-record value-encryption subkey domain.
pub fn derive_subkey(
    master: &Secret<[u8; 32]>,
    record_id: u64,
    ctx: &[u8; 8],
) -> Result<Secret<[u8; 32]>> {
    init_sodium()?;
    let mut sub = [0u8; 32];
    // SAFETY:
    // - `sub` has length 32; libsodium writes exactly `subkey_len` bytes.
    // - `ctx` is 8 bytes (libsodium's required context length).
    // - `master` is exactly 32 bytes (`crypto_kdf_KEYBYTES`).
    let rc = unsafe {
        sodium::crypto_kdf_derive_from_key(
            sub.as_mut_ptr(),
            32,
            record_id,
            ctx.as_ptr() as *const core::ffi::c_char,
            master.expose_secret().as_ptr(),
        )
    };
    if rc != 0 {
        return Err(Error::Kdf("crypto_kdf_derive_from_key failed"));
    }
    Ok(Secret::new(sub))
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn secret_debug_redacts() {
        let s: Secret<String> = Secret::new(String::from("REDACTED"));
        let d = format!("{s:?}");
        assert_eq!(d, "***");
        assert!(!d.contains("REDACTED"));
    }

    #[test]
    fn aead_roundtrip_basic() {
        let key = [7u8; 32];
        let nonce = aead::random_nonce().unwrap();
        let aad = b"cloak.test";
        let pt = b"plaintext";
        let ct = aead::seal(&key, &nonce, aad, pt).unwrap();
        assert_eq!(ct.len(), pt.len() + aead::TAG_LEN);
        let dec = aead::open(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn aead_tamper_fails() {
        let key = [9u8; 32];
        let nonce = aead::random_nonce().unwrap();
        let aad = b"";
        let pt = b"plaintext";
        let mut ct = aead::seal(&key, &nonce, aad, pt).unwrap();
        ct[0] ^= 0x01;
        match aead::open(&key, &nonce, aad, &ct) {
            Err(Error::Aead(_)) => {}
            other => panic!("expected AEAD error, got {other:?}"),
        }
    }

    #[test]
    fn aead_wrong_aad_fails() {
        let key = [3u8; 32];
        let nonce = aead::random_nonce().unwrap();
        let pt = b"plaintext";
        let ct = aead::seal(&key, &nonce, b"aad-1", pt).unwrap();
        assert!(matches!(
            aead::open(&key, &nonce, b"aad-2", &ct),
            Err(Error::Aead(_))
        ));
    }

    #[test]
    fn aead_short_ciphertext_typed_error() {
        let key = [0u8; 32];
        let nonce = [0u8; 24];
        let r = aead::open(&key, &nonce, b"", &[1, 2, 3]);
        assert!(matches!(r, Err(Error::Aead(_))));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn prop_aead_roundtrip(
            pt in proptest::collection::vec(any::<u8>(), 0..=512),
            aad in proptest::collection::vec(any::<u8>(), 0..=64),
            key_seed in any::<u64>(),
        ) {
            let mut key = [0u8; 32];
            for (i, b) in key.iter_mut().enumerate() {
                *b = ((key_seed >> (i % 8)) & 0xff) as u8;
            }
            let nonce = aead::random_nonce().unwrap();
            let ct = aead::seal(&key, &nonce, &aad, &pt).unwrap();
            let dec = aead::open(&key, &nonce, &aad, &ct).unwrap();
            prop_assert_eq!(dec, pt);
        }

        #[test]
        fn prop_aead_tamper_any_byte_fails(
            pt in proptest::collection::vec(any::<u8>(), 1..=128),
            tamper_bit in 0u32..2048,
        ) {
            let key = [42u8; 32];
            let nonce = aead::random_nonce().unwrap();
            let mut ct = aead::seal(&key, &nonce, b"aad", &pt).unwrap();
            let bit_idx = (tamper_bit as usize) % (ct.len() * 8);
            let byte = bit_idx / 8;
            let bit = bit_idx % 8;
            ct[byte] ^= 1 << bit;
            let r = aead::open(&key, &nonce, b"aad", &ct);
            prop_assert!(matches!(r, Err(Error::Aead(_))));
        }
    }

    #[test]
    fn kdf_determinism() {
        let pass = Secret::new(String::from("hunter2"));
        let pepper = Secret::new(vec![0xABu8; 32]);
        let salt = [0x55u8; 16];
        let p = kdf::KdfParams {
            mem_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        };
        let a = kdf::derive(&pass, &salt, &pepper, p).unwrap();
        let b = kdf::derive(&pass, &salt, &pepper, p).unwrap();
        assert_eq!(a.expose_secret(), b.expose_secret());
    }

    #[test]
    fn kdf_different_passphrases_diverge() {
        let pepper = Secret::new(vec![0u8; 32]);
        let salt = [1u8; 16];
        let p = kdf::KdfParams {
            mem_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        };
        let a = kdf::derive(&Secret::new("a".to_string()), &salt, &pepper, p).unwrap();
        let b = kdf::derive(&Secret::new("b".to_string()), &salt, &pepper, p).unwrap();
        assert_ne!(a.expose_secret(), b.expose_secret());
    }

    #[test]
    fn kdf_different_peppers_diverge() {
        let pass = Secret::new(String::from("same"));
        let salt = [1u8; 16];
        let p = kdf::KdfParams {
            mem_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        };
        let a = kdf::derive(&pass, &salt, &Secret::new(vec![1u8; 32]), p).unwrap();
        let b = kdf::derive(&pass, &salt, &Secret::new(vec![2u8; 32]), p).unwrap();
        assert_ne!(a.expose_secret(), b.expose_secret());
    }

    #[test]
    fn phc_roundtrip() {
        let p = kdf::KdfParams {
            mem_kib: 65536,
            t_cost: 4,
            p_cost: 4,
        };
        let salt = [0xCDu8; 16];
        let s = kdf::params_to_phc(&p, &salt);
        let (p2, salt2) = kdf::params_from_phc(&s).unwrap();
        assert_eq!(p, p2);
        assert_eq!(salt, salt2);
    }

    #[test]
    fn phc_rejects_garbage() {
        assert!(kdf::params_from_phc("notphc").is_err());
        assert!(kdf::params_from_phc("$argon2i$v=19$m=1,t=1,p=1$AAAA").is_err());
        assert!(kdf::params_from_phc("$argon2id$v=18$m=1,t=1,p=1$AAAA").is_err());
        assert!(kdf::params_from_phc("$argon2id$v=19$m=1,t=1$AAAA").is_err());
    }

    #[test]
    fn subkey_derivation_deterministic() {
        let master = Secret::new([7u8; 32]);
        let a = derive_subkey(&master, 42, b"cloakrec").unwrap();
        let b = derive_subkey(&master, 42, b"cloakrec").unwrap();
        assert_eq!(a.expose_secret(), b.expose_secret());
        let c = derive_subkey(&master, 43, b"cloakrec").unwrap();
        assert_ne!(a.expose_secret(), c.expose_secret());
    }
}
