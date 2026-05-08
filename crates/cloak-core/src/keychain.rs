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
/// Account name (within `SERVICE`) for the rollback-counter mirror item.
///
/// The counter mirror is a separate keychain item from the pepper so it
/// can be read/written at every vault open without touching the pepper
/// item's ACL surface (and so a stale mirror on its own can never leak
/// pepper material). Stored as 8 bytes, big-endian `u64`.
pub const ROLLBACK_COUNTER_ACCOUNT: &str = "vault.rollback-counter.v1";

/// Length of the random pepper, in bytes.
pub const PEPPER_LEN: usize = 32;

/// On-disk filename for the file-fallback rollback-counter mirror.
///
/// When `CLOAK_PEPPER_FILE` is set we cannot write the mirror into the
/// OS keychain; instead we write it to a 0600 file alongside the pepper
/// file. See [`THREAT_MODEL.md`] — in this fallback an attacker who can
/// roll the vault back can also roll the counter file back in lockstep,
/// defeating the detection. The OS keychain path is the real defense.
const ROLLBACK_COUNTER_FILENAME: &str = "rollback-counter";

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

// -------------------------------------------------------------------------
// Rollback-counter mirror
// -------------------------------------------------------------------------
//
// The vault file's `meta.monotonic_counter` is mirrored to a second OS
// keychain item (or, in the file-fallback case, a sibling file). Every
// vault open compares the file counter to the mirror:
//
// - file == mirror   → ok
// - file >  mirror   → vault was bumped externally (e.g. an rsync from
//                      another device); refresh the mirror to the file.
// - file <  mirror   → ROLLBACK. Refuse to open with
//                      `Error::VaultRollbackDetected`.
// - mirror missing   → first run after upgrade; seed mirror from file.
//
// Order on writes: write the file first (the source of truth), then
// mirror to the keychain. A failed mirror write is logged but does NOT
// fail the vault write — the file's counter is what protects against
// future rollbacks; the mirror only catches them at *read* time.

/// Read the rollback-counter mirror, honoring `CLOAK_PEPPER_FILE` first.
/// Returns `Ok(None)` if no mirror has been written yet (fresh install or
/// upgrade from a Cloak that didn't have the mirror).
pub fn read_keychain_counter() -> Result<Option<u64>> {
    #[cfg(any(test, feature = "test-util"))]
    if rollback_mirror_disabled() {
        return Ok(None);
    }
    if let Some(path) = std::env::var_os(PEPPER_FILE_ENV) {
        return file_counter_read(std::path::Path::new(&path));
    }
    keychain_counter_read()
}

/// Write the rollback-counter mirror to the OS keychain (or the file
/// fallback). The keychain is best-effort by design: on any failure the
/// caller should warn but not abort the surrounding write — the file
/// counter is the source of truth.
pub fn mirror_counter(value: u64) -> Result<()> {
    #[cfg(any(test, feature = "test-util"))]
    if rollback_mirror_disabled() {
        return Ok(());
    }
    if let Some(path) = std::env::var_os(PEPPER_FILE_ENV) {
        return file_counter_write(std::path::Path::new(&path), value);
    }
    keychain_counter_write(value)
}

/// Test-only escape hatch. When `CLOAK_DISABLE_ROLLBACK_MIRROR=1` is
/// set the mirror behaves as if it were absent (reads return `None`,
/// writes are no-ops). This exists so unit and integration tests in
/// other crates can exercise the vault without poisoning the OS
/// keychain or requiring a working session bus.
///
/// The constant, the helper, and the early-return calls in
/// `read_keychain_counter` / `mirror_counter` are all gated behind
/// `#[cfg(any(test, feature = "test-util"))]` so release binaries
/// compiled without `--features test-util` cannot honor the env var
/// at all — a same-UID attacker cannot disable A7 read-side rollback
/// detection by setting it in their environment.
#[cfg(any(test, feature = "test-util"))]
const DISABLE_MIRROR_ENV: &str = "CLOAK_DISABLE_ROLLBACK_MIRROR";

#[cfg(any(test, feature = "test-util"))]
fn rollback_mirror_disabled() -> bool {
    std::env::var_os(DISABLE_MIRROR_ENV)
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Encode/decode helpers — 8 bytes big-endian.
fn encode_counter(v: u64) -> [u8; 8] {
    v.to_be_bytes()
}
fn decode_counter(bytes: &[u8]) -> Result<u64> {
    if bytes.len() != 8 {
        return Err(Error::Keychain(format!(
            "rollback counter mirror has wrong length: {} (expected 8)",
            bytes.len()
        )));
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(bytes);
    Ok(u64::from_be_bytes(a))
}

/// Resolve the file-fallback counter path: sibling of the pepper file.
fn counter_file_path(pepper_path: &std::path::Path) -> std::path::PathBuf {
    pepper_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(ROLLBACK_COUNTER_FILENAME)
}

fn file_counter_read(pepper_path: &std::path::Path) -> Result<Option<u64>> {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let path = counter_file_path(pepper_path);
    if !path.exists() {
        return Ok(None);
    }
    #[cfg(unix)]
    {
        let meta = std::fs::metadata(&path)
            .map_err(|e| Error::Keychain(format!("stat counter file: {e}")))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(Error::Keychain(format!(
                "rollback counter file {} is world/group accessible (mode {:o}); refusing to load",
                path.display(),
                mode
            )));
        }
    }
    let bytes =
        std::fs::read(&path).map_err(|e| Error::Keychain(format!("read counter file: {e}")))?;
    Ok(Some(decode_counter(&bytes)?))
}

fn file_counter_write(pepper_path: &std::path::Path, value: u64) -> Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let path = counter_file_path(pepper_path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Keychain(format!("create counter dir: {e}")))?;
        }
    }
    // Write to a temp sibling and rename for atomicity. The 0600 mode is
    // applied before any bytes hit the disk via `OpenOptions::mode` is not
    // strictly portable; we set permissions immediately after open.
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| Error::Keychain(format!("create counter tmp: {e}")))?;
        #[cfg(unix)]
        {
            let perms = std::fs::Permissions::from_mode(0o600);
            f.set_permissions(perms)
                .map_err(|e| Error::Keychain(format!("chmod counter tmp: {e}")))?;
        }
        f.write_all(&encode_counter(value))
            .map_err(|e| Error::Keychain(format!("write counter tmp: {e}")))?;
        f.sync_all()
            .map_err(|e| Error::Keychain(format!("sync counter tmp: {e}")))?;
    }
    std::fs::rename(&tmp, &path)
        .map_err(|e| Error::Keychain(format!("rename counter tmp: {e}")))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn keychain_counter_read() -> Result<Option<u64>> {
    use security_framework::passwords::get_generic_password;
    match get_generic_password(SERVICE, ROLLBACK_COUNTER_ACCOUNT) {
        Ok(bytes) => Ok(Some(decode_counter(&bytes)?)),
        Err(e) => {
            // `errSecItemNotFound` (-25300) is the "no mirror yet" signal
            // — first run after upgrade. Anything else is an error.
            if e.code() == -25300 {
                Ok(None)
            } else {
                Err(Error::Keychain(format!(
                    "get_generic_password (rollback counter): {e}"
                )))
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn keychain_counter_write(value: u64) -> Result<()> {
    use security_framework::passwords::set_generic_password;
    set_generic_password(SERVICE, ROLLBACK_COUNTER_ACCOUNT, &encode_counter(value))
        .map_err(|e| Error::Keychain(format!("set_generic_password (rollback counter): {e}")))
}

#[cfg(target_os = "linux")]
fn keychain_counter_read() -> Result<Option<u64>> {
    linux_secret_service::counter_read()
}

#[cfg(target_os = "linux")]
fn keychain_counter_write(value: u64) -> Result<()> {
    linux_secret_service::counter_write(value)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn keychain_counter_read() -> Result<Option<u64>> {
    Err(Error::Keychain(
        "OS keychain unsupported on this platform in v1.0; set CLOAK_PEPPER_FILE to use a file-backed rollback counter".to_string(),
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn keychain_counter_write(_value: u64) -> Result<()> {
    Err(Error::Keychain(
        "OS keychain unsupported on this platform in v1.0; set CLOAK_PEPPER_FILE to use a file-backed rollback counter".to_string(),
    ))
}

/// Delete the rollback-counter mirror item. Used by tests and `cloak destroy`.
#[cfg(target_os = "macos")]
pub fn delete_rollback_counter() -> Result<()> {
    use security_framework::passwords::delete_generic_password;
    match delete_generic_password(SERVICE, ROLLBACK_COUNTER_ACCOUNT) {
        Ok(()) => Ok(()),
        // -25300 == errSecItemNotFound: nothing to delete is success.
        Err(e) => {
            if e.code() == -25300 {
                Ok(())
            } else {
                Err(Error::Keychain(format!(
                    "delete_generic_password (rollback counter): {e}"
                )))
            }
        }
    }
}

/// Delete the rollback-counter mirror via Secret Service.
#[cfg(target_os = "linux")]
pub fn delete_rollback_counter() -> Result<()> {
    linux_secret_service::counter_delete()
}

/// Stub for platforms without an OS keychain integration yet.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn delete_rollback_counter() -> Result<()> {
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
    use super::{decode_counter, encode_counter};
    use super::{ACCOUNT, PEPPER_LEN, ROLLBACK_COUNTER_ACCOUNT, SERVICE};
    use crate::crypto::Secret;
    use crate::error::{Error, Result};
    use secret_service::blocking::{Collection, SecretService};
    use secret_service::EncryptionType;
    use std::collections::HashMap;

    /// Item label shown in keyring UIs (e.g. seahorse).
    const ITEM_LABEL: &str = "Cloak vault pepper";
    /// Item label for the rollback-counter mirror.
    const COUNTER_LABEL: &str = "Cloak vault rollback counter";
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

    /// Counter-mirror search attributes — same `service`, distinct
    /// `account` so the pepper item is never accidentally read or
    /// overwritten.
    fn counter_attrs() -> HashMap<&'static str, &'static str> {
        let mut m = HashMap::new();
        m.insert("service", SERVICE);
        m.insert("account", ROLLBACK_COUNTER_ACCOUNT);
        m
    }

    pub(super) fn counter_read() -> Result<Option<u64>> {
        let ss = connect()?;
        let search = ss.search_items(counter_attrs()).map_err(dbus_unavailable)?;
        let mut hit = search.unlocked.into_iter().next();
        if hit.is_none() {
            if let Some(item) = search.locked.into_iter().next() {
                item.unlock().map_err(dbus_unavailable)?;
                hit = Some(item);
            }
        }
        match hit {
            Some(item) => {
                let bytes = item.get_secret().map_err(dbus_unavailable)?;
                Ok(Some(decode_counter(&bytes)?))
            }
            None => Ok(None),
        }
    }

    pub(super) fn counter_write(value: u64) -> Result<()> {
        let ss = connect()?;
        let collection = unlocked_collection(&ss)?;
        collection
            .create_item(
                COUNTER_LABEL,
                counter_attrs(),
                &encode_counter(value),
                /* replace = */ true,
                CONTENT_TYPE,
            )
            .map_err(dbus_unavailable)?;
        Ok(())
    }

    pub(super) fn counter_delete() -> Result<()> {
        let ss = connect()?;
        let search = ss.search_items(counter_attrs()).map_err(dbus_unavailable)?;
        for item in search.unlocked.into_iter().chain(search.locked) {
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

#[cfg(test)]
mod rollback_counter_tests {
    //! Coverage for the rollback-counter encoding helpers and the file
    //! fallback. End-to-end "did the vault refuse to open?" coverage
    //! lives in `tests/rollback_mirror.rs` so it can mutate env vars
    //! without poisoning sibling tests.

    use super::*;
    use tempfile::TempDir;

    #[test]
    fn encode_decode_roundtrip() {
        for v in [0u64, 1, 42, u64::MAX / 2, u64::MAX] {
            let bytes = encode_counter(v);
            assert_eq!(bytes.len(), 8);
            assert_eq!(decode_counter(&bytes).unwrap(), v);
        }
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert!(matches!(decode_counter(&[]), Err(Error::Keychain(_))));
        assert!(matches!(decode_counter(&[0u8; 7]), Err(Error::Keychain(_))));
        assert!(matches!(decode_counter(&[0u8; 9]), Err(Error::Keychain(_))));
    }

    #[test]
    fn file_counter_write_then_read_roundtrip() {
        let dir = TempDir::new().unwrap();
        let pepper = dir.path().join("pepper");
        // No counter file yet → read returns Ok(None).
        assert!(matches!(file_counter_read(&pepper), Ok(None)));
        // Write, read back.
        file_counter_write(&pepper, 12345).unwrap();
        assert_eq!(file_counter_read(&pepper).unwrap(), Some(12345));
        // Overwrite with a new value.
        file_counter_write(&pepper, 99).unwrap();
        assert_eq!(file_counter_read(&pepper).unwrap(), Some(99));
    }

    #[cfg(unix)]
    #[test]
    fn file_counter_rejects_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let pepper = dir.path().join("pepper");
        file_counter_write(&pepper, 7).unwrap();
        // Loosen the permissions to simulate a misconfigured deployment.
        let counter_path = counter_file_path(&pepper);
        std::fs::set_permissions(&counter_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let r = file_counter_read(&pepper);
        match r {
            Err(Error::Keychain(msg)) => assert!(
                msg.contains("world/group accessible"),
                "unexpected message: {msg}"
            ),
            other => panic!("expected Keychain error, got {other:?}"),
        }
    }
}
