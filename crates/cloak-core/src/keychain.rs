//! OS-keychain pepper accessor.
//!
//! The "pepper" is a 32-byte random secret stored in the OS-managed
//! keychain (NOT on disk in the vault file). It is used as the HMAC key
//! for the keyed-mode Argon2id construction in [`crate::crypto::kdf`]:
//! an attacker who exfiltrates the vault file alone cannot run Argon2id.
//!
//! Service / account namespace:
//! - service = `"dev.cloak"`
//! - account = `"vault.pepper"`
//!
//! v0.1 supports macOS only. Linux / Windows return a typed error so
//! callers can degrade gracefully (e.g. `--insecure-pepper-file`).

use crate::crypto::Secret;
use crate::error::{Error, Result};

/// Service identifier under which the pepper item lives in the keychain.
pub const SERVICE: &str = "dev.cloak";
/// Account name (within `SERVICE`) for the pepper item.
pub const ACCOUNT: &str = "vault.pepper";

/// Length of the random pepper, in bytes.
pub const PEPPER_LEN: usize = 32;

/// Env var: if set, points at a file holding the pepper bytes.
///
/// This is a v0.1 escape hatch (also the spec'd Linux fallback) for
/// environments where the OS keychain is not available — headless
/// servers, CI runners, dev sandboxes that cannot prompt for keychain
/// authorization. The file is read with `0600` mode requirements
/// **enforced** on read; refusing to load a world-readable pepper file
/// is intentional. Generation is on-demand: if the file does not exist,
/// a fresh 32-byte pepper is written there with mode `0600`.
///
/// This is documented as **insecure relative to the OS keychain** —
/// `THREAT_MODEL.md` lists it as a residual risk for v0.1.
pub const PEPPER_FILE_ENV: &str = "CLOAK_PEPPER_FILE";

/// Fetch the pepper, honoring the `CLOAK_PEPPER_FILE` override first and
/// falling back to the OS keychain.
pub fn get_or_create_pepper() -> Result<Secret<Vec<u8>>> {
    if let Some(path) = std::env::var_os(PEPPER_FILE_ENV) {
        return file_pepper(std::path::Path::new(&path));
    }
    keychain_pepper()
}

/// File-backed pepper. Reads or creates `path` with mode `0600`.
fn file_pepper(path: &std::path::Path) -> Result<Secret<Vec<u8>>> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    if path.exists() {
        let bytes =
            std::fs::read(path).map_err(|e| Error::Keychain(format!("read pepper file: {e}")))?;
        if bytes.len() != PEPPER_LEN {
            return Err(Error::Keychain(format!(
                "pepper file has wrong length: {} (expected {})",
                bytes.len(),
                PEPPER_LEN
            )));
        }
        #[cfg(unix)]
        {
            let meta = std::fs::metadata(path)
                .map_err(|e| Error::Keychain(format!("stat pepper file: {e}")))?;
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(Error::Keychain(format!(
                    "pepper file {} is world/group accessible (mode {:o}); refusing to load",
                    path.display(),
                    mode
                )));
            }
        }
        return Ok(Secret::new(bytes));
    }

    let pepper = crate::crypto::aead::random_bytes(PEPPER_LEN)?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Keychain(format!("create pepper dir: {e}")))?;
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| Error::Keychain(format!("create pepper file: {e}")))?;
    #[cfg(unix)]
    {
        let perms = std::fs::Permissions::from_mode(0o600);
        f.set_permissions(perms)
            .map_err(|e| Error::Keychain(format!("chmod pepper file: {e}")))?;
    }
    f.write_all(&pepper)
        .map_err(|e| Error::Keychain(format!("write pepper file: {e}")))?;
    f.sync_all()
        .map_err(|e| Error::Keychain(format!("sync pepper file: {e}")))?;
    Ok(Secret::new(pepper))
}

#[cfg(target_os = "macos")]
fn keychain_pepper() -> Result<Secret<Vec<u8>>> {
    use security_framework::passwords::{get_generic_password, set_generic_password};

    match get_generic_password(SERVICE, ACCOUNT) {
        Ok(bytes) => {
            if bytes.len() != PEPPER_LEN {
                return Err(Error::Keychain(format!(
                    "pepper has wrong length: {} (expected {})",
                    bytes.len(),
                    PEPPER_LEN
                )));
            }
            Ok(Secret::new(bytes))
        }
        Err(_) => {
            // Either missing or another keychain error. Generate a new
            // pepper and try to store it. If storing fails we report the
            // store error.
            let pepper = crate::crypto::aead::random_bytes(PEPPER_LEN)?;
            set_generic_password(SERVICE, ACCOUNT, &pepper)
                .map_err(|e| Error::Keychain(format!("set_generic_password: {e}")))?;
            Ok(Secret::new(pepper))
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn keychain_pepper() -> Result<Secret<Vec<u8>>> {
    Err(Error::Keychain(
        "OS keychain unsupported on this platform in v0.1; set CLOAK_PEPPER_FILE to use a file-backed pepper".to_string(),
    ))
}

/// Delete the pepper item (used by tests and `cloak destroy`).
#[cfg(target_os = "macos")]
pub fn delete_pepper() -> Result<()> {
    use security_framework::passwords::delete_generic_password;
    match delete_generic_password(SERVICE, ACCOUNT) {
        Ok(()) => Ok(()),
        Err(e) => Err(Error::Keychain(format!("delete_generic_password: {e}"))),
    }
}

/// Stub for non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub fn delete_pepper() -> Result<()> {
    Err(Error::Keychain(
        "unsupported on this platform in v0.1".to_string(),
    ))
}
