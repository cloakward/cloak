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
//! v0.1 supports macOS via Security Framework and Linux via the
//! freedesktop Secret Service (GNOME Keyring / KWallet) over D-Bus.
//! Windows returns a typed error so callers can degrade gracefully
//! (e.g. `CLOAK_PEPPER_FILE`).

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

#[cfg(target_os = "linux")]
fn keychain_pepper() -> Result<Secret<Vec<u8>>> {
    linux_secret_service::pepper_get_or_create()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn keychain_pepper() -> Result<Secret<Vec<u8>>> {
    Err(Error::Keychain(
        "OS keychain unsupported on this platform in v1.0; set CLOAK_PEPPER_FILE to use a file-backed pepper".to_string(),
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

/// Delete the pepper item via Secret Service.
#[cfg(target_os = "linux")]
pub fn delete_pepper() -> Result<()> {
    linux_secret_service::pepper_delete()
}

/// Stub for platforms without an OS keychain integration yet.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn delete_pepper() -> Result<()> {
    Err(Error::Keychain(
        "unsupported on this platform in v1.0".to_string(),
    ))
}

/// Linux-specific Secret Service plumbing.
///
/// We isolate the `secret-service` crate calls here so the rest of the
/// module remains portable. The blocking API is intentional: the pepper
/// fetch happens once at unlock and fits naturally into a synchronous
/// path. Connection failures (no session bus, e.g. SSH session) become a
/// typed `Error::Keychain` with explicit guidance to set
/// `CLOAK_PEPPER_FILE` for the headless case.
#[cfg(target_os = "linux")]
mod linux_secret_service {
    use super::{ACCOUNT, PEPPER_LEN, SERVICE};
    use crate::crypto::Secret;
    use crate::error::{Error, Result};
    use secret_service::blocking::{Collection, SecretService};
    use secret_service::EncryptionType;
    use std::collections::HashMap;

    /// Item label shown in keyring UIs (e.g. seahorse).
    const ITEM_LABEL: &str = "Cloak vault pepper";
    /// `Item::set_secret` content-type for raw bytes.
    const CONTENT_TYPE: &str = "application/octet-stream";

    fn dbus_unavailable<E: std::fmt::Display>(e: E) -> Error {
        // libsecret's error display text never contains secret material;
        // including it helps users diagnose missing-bus / locked-keyring
        // states without exposing pepper bytes.
        Error::Keychain(format!(
            "secret service unavailable ({e}); set CLOAK_PEPPER_FILE to use a file-backed pepper"
        ))
    }

    /// Build the search-attribute map used both to look up and to create
    /// the pepper item. Keeping these identical is what lets a caller
    /// find an item it (or a previous run) created.
    fn attrs() -> HashMap<&'static str, &'static str> {
        let mut m = HashMap::new();
        m.insert("service", SERVICE);
        m.insert("account", ACCOUNT);
        m
    }

    /// Connect to the session bus, with `EncryptionType::Plain`. The DH
    /// session encryption is only useful on the wire to the bus daemon;
    /// for a UID-local AF_UNIX bus there's no MITM to defeat, and Plain
    /// avoids extra crypto in the runtime path.
    fn connect<'a>() -> Result<SecretService<'a>> {
        SecretService::connect(EncryptionType::Plain).map_err(dbus_unavailable)
    }

    /// Pick a usable, unlocked collection. Try the default alias first,
    /// then `login`. If both refuse to unlock — which is what happens on
    /// a headless SSH session with no agent — surface a typed error.
    fn unlocked_collection<'a>(ss: &'a SecretService<'a>) -> Result<Collection<'a>> {
        if let Ok(c) = ss.get_default_collection() {
            if try_unlock(&c).is_ok() {
                return Ok(c);
            }
        }
        if let Ok(c) = ss.get_collection_by_alias("login") {
            if try_unlock(&c).is_ok() {
                return Ok(c);
            }
        }
        Err(Error::Keychain(
            "secret service unavailable (no unlocked collection); \
             set CLOAK_PEPPER_FILE to use a file-backed pepper"
                .to_string(),
        ))
    }

    fn try_unlock(c: &Collection<'_>) -> Result<()> {
        match c.is_locked() {
            Ok(false) => Ok(()),
            Ok(true) => c.unlock().map_err(dbus_unavailable),
            Err(e) => Err(dbus_unavailable(e)),
        }
    }

    pub(super) fn pepper_get_or_create() -> Result<Secret<Vec<u8>>> {
        let ss = connect()?;

        // 1. Look up an existing item across all collections.
        let search = ss.search_items(attrs()).map_err(dbus_unavailable)?;
        // SearchItemsResult separates unlocked from locked; we accept
        // either, unlocking on demand.
        let mut hit = search.unlocked.into_iter().next();
        if hit.is_none() {
            if let Some(item) = search.locked.into_iter().next() {
                item.unlock().map_err(dbus_unavailable)?;
                hit = Some(item);
            }
        }

        if let Some(item) = hit {
            let bytes = item.get_secret().map_err(dbus_unavailable)?;
            if bytes.len() != PEPPER_LEN {
                return Err(Error::Keychain(format!(
                    "pepper has wrong length: {} (expected {})",
                    bytes.len(),
                    PEPPER_LEN
                )));
            }
            return Ok(Secret::new(bytes));
        }

        // 2. Miss: pick an unlocked collection and create the item.
        let collection = unlocked_collection(&ss)?;
        let pepper = crate::crypto::aead::random_bytes(PEPPER_LEN)?;
        collection
            .create_item(
                ITEM_LABEL,
                attrs(),
                &pepper,
                /* replace = */ true,
                CONTENT_TYPE,
            )
            .map_err(dbus_unavailable)?;
        Ok(Secret::new(pepper))
    }

    pub(super) fn pepper_delete() -> Result<()> {
        let ss = connect()?;
        let search = ss.search_items(attrs()).map_err(dbus_unavailable)?;
        for item in search.unlocked.into_iter().chain(search.locked) {
            // Best-effort: unlock so delete can proceed, then delete.
            let _ = item.unlock();
            item.delete().map_err(dbus_unavailable)?;
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        //! Linux Secret Service tests.
        //!
        //! The two tests that touch a real session bus are gated on
        //! `RUN_LINUX_SECRET_SERVICE_TEST=1` (and `#[ignore]`d) so they
        //! never run in CI environments without a session bus. Run
        //! manually on a Linux desktop with:
        //!
        //!   RUN_LINUX_SECRET_SERVICE_TEST=1 \
        //!     cargo test -p cloak-core --lib keychain -- --ignored
        //!
        //! Coverage:
        //! - `missing_item_creates`: cold start writes a fresh item,
        //!   second call returns the same bytes.
        //! - `wrong_length_item_rejected`: a bogus-length item is
        //!   surfaced as a typed `Error::Keychain`, not a panic.
        //! - `no_dbus_returns_typed_error`: with the session bus
        //!   address pointed at nothing, `pepper_get_or_create()`
        //!   returns a `Keychain` error whose message tells the user
        //!   to set `CLOAK_PEPPER_FILE`. This test is gate-free — it
        //!   forces the failure path and is safe to run anywhere.

        use super::*;
        use crate::error::Error;

        fn gate() -> bool {
            std::env::var_os("RUN_LINUX_SECRET_SERVICE_TEST").is_some()
        }

        /// Cold-start: ensure no pepper, then `pepper_get_or_create`
        /// produces a 32-byte secret and a second call returns the
        /// same bytes.
        #[test]
        #[ignore = "requires a Linux desktop session bus; gate with RUN_LINUX_SECRET_SERVICE_TEST=1"]
        fn missing_item_creates() {
            if !gate() {
                return;
            }
            // Best-effort cleanup; ignore "not found".
            let _ = pepper_delete();
            let p1 = pepper_get_or_create().expect("create on miss");
            assert_eq!(p1.expose_secret().len(), PEPPER_LEN);
            let p2 = pepper_get_or_create().expect("hit on second call");
            assert_eq!(p1.expose_secret(), p2.expose_secret());
            let _ = pepper_delete();
        }

        /// Inject an item with the wrong length and confirm the read
        /// path returns a typed `Error::Keychain` rather than panicking.
        #[test]
        #[ignore = "requires a Linux desktop session bus; gate with RUN_LINUX_SECRET_SERVICE_TEST=1"]
        fn wrong_length_item_rejected() {
            if !gate() {
                return;
            }
            let _ = pepper_delete();
            let ss = connect().expect("session bus");
            let collection = unlocked_collection(&ss).expect("unlocked collection");
            collection
                .create_item(ITEM_LABEL, attrs(), b"too-short", true, CONTENT_TYPE)
                .expect("seed bogus item");

            match pepper_get_or_create() {
                Err(Error::Keychain(msg)) => {
                    assert!(
                        msg.contains("wrong length"),
                        "unexpected keychain message: {msg}"
                    );
                }
                Ok(_) => panic!("expected Error::Keychain, got Ok"),
                Err(e) => panic!("expected Error::Keychain, got {e:?}"),
            }
            let _ = pepper_delete();
        }

        /// Force a connection failure by pointing the session bus
        /// address at a path that isn't a socket. The error must be a
        /// `Keychain` error whose message tells the user to set
        /// `CLOAK_PEPPER_FILE`. This test does NOT need a real bus and
        /// is therefore not gated.
        #[test]
        fn no_dbus_returns_typed_error() {
            // Save and override env vars so we don't poison the rest
            // of the test run.
            let prev_bus = std::env::var_os("DBUS_SESSION_BUS_ADDRESS");
            let prev_xdg = std::env::var_os("XDG_RUNTIME_DIR");
            // SAFETY: required by std 1.84+ for `set_var`/`remove_var`.
            // Mutation is restored before this function returns. This
            // test deliberately does not run in parallel with anything
            // that depends on these vars; it's the only test in the
            // crate that mutates them.
            unsafe {
                std::env::set_var(
                    "DBUS_SESSION_BUS_ADDRESS",
                    "unix:path=/nonexistent/cloak-w7-test-bus",
                );
                std::env::set_var("XDG_RUNTIME_DIR", "/nonexistent/cloak-w7-xdg");
            }

            let r = pepper_get_or_create();

            unsafe {
                match prev_bus {
                    Some(v) => std::env::set_var("DBUS_SESSION_BUS_ADDRESS", v),
                    None => std::env::remove_var("DBUS_SESSION_BUS_ADDRESS"),
                }
                match prev_xdg {
                    Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
                    None => std::env::remove_var("XDG_RUNTIME_DIR"),
                }
            }

            match r {
                Err(Error::Keychain(msg)) => {
                    assert!(
                        msg.contains("CLOAK_PEPPER_FILE"),
                        "expected guidance to set CLOAK_PEPPER_FILE, got: {msg}"
                    );
                }
                Ok(_) => panic!("expected Error::Keychain when D-Bus is unavailable, got Ok"),
                Err(e) => panic!("expected Error::Keychain, got {e:?}"),
            }
        }
    }
}
