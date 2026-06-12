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
/// Account name (within `SERVICE`) for the rollback-state mirror item.
///
/// The rollback mirror is a separate keychain item from the pepper so it
/// can be read/written at every vault open without touching the pepper
/// item's ACL surface (and so a stale mirror on its own can never leak
/// pepper material). Stored as `counter_be(u64) || vault_state_sha256`.
pub const ROLLBACK_COUNTER_ACCOUNT: &str = "vault.rollback-counter.v1";
/// Account name for an in-progress rollback-state mirror update.
pub const ROLLBACK_COUNTER_PENDING_ACCOUNT: &str = "vault.rollback-counter-pending.v1";
/// Account name for the audit-log head anchor.
pub const AUDIT_HEAD_ACCOUNT: &str = "audit.head.v1";
/// Account name for an in-progress audit-log head update.
pub const AUDIT_HEAD_PENDING_ACCOUNT: &str = "audit.head-pending.v1";

/// Length of the random pepper, in bytes.
pub const PEPPER_LEN: usize = 32;

/// On-disk filename for the file-fallback rollback-counter mirror.
///
/// When `CLOAK_PEPPER_FILE` is set we cannot write the mirror into the
/// OS keychain; instead we write it to a 0600 file alongside the pepper
/// file. See [`THREAT_MODEL.md`] - in this fallback an attacker who can
/// roll the vault back can also roll the counter file back in lockstep,
/// defeating the detection. The OS keychain path is the real defense.
const ROLLBACK_COUNTER_FILENAME: &str = "rollback-counter";
const ROLLBACK_COUNTER_PENDING_FILENAME: &str = "rollback-counter-pending";
const PENDING_COUNTER_MAGIC: &[u8; 8] = b"CLKRCP01";
const AUDIT_HEAD_FILENAME: &str = "audit-head";
const AUDIT_HEAD_PENDING_FILENAME: &str = "audit-head-pending";
const PENDING_AUDIT_HEAD_MAGIC: &[u8; 8] = b"CLKAHP01";

/// Rollback-state mirror value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RollbackState {
    /// Monotonic counter stored in the vault file.
    pub counter: u64,
    /// SHA-256 digest of the logical vault contents for that counter.
    pub digest: [u8; 32],
}

impl RollbackState {
    /// Sentinel used for the pre-initialized vault state.
    pub const fn zero() -> Self {
        Self {
            counter: 0,
            digest: [0u8; 32],
        }
    }
}

/// Rollback mirror state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackCounterMirror {
    /// The mirror is cleanly committed to this vault state.
    Committed(RollbackState),
    /// A write was in flight. `committed` is the last durable value before
    /// the SQLite transaction; `pending` is the state written by that
    /// transaction if it committed before the process exited.
    Pending {
        /// Last known committed state before the pending write.
        committed: RollbackState,
        /// State expected after the pending SQLite transaction commits.
        pending: RollbackState,
    },
    /// Pre-v1.0.2 mirrors stored only the plaintext counter. Normal vault
    /// open fails closed on these because they cannot prove pre-upgrade
    /// history; operators must explicitly adopt the reviewed current vault
    /// state.
    LegacyCounter(u64),
}

/// Audit-log head anchored outside `audit.jsonl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditHead {
    /// Final sequence number in the audit log.
    pub seq: u64,
    /// SHA-256 hash of the final audit entry's canonical JSON, or all zeroes
    /// for an empty audit log.
    pub hash: [u8; 32],
}

/// Committed or in-flight audit-head anchor state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditHeadAnchor {
    /// The anchor is cleanly committed to this head.
    Committed(AuditHead),
    /// A write was in flight. `committed` is the durable head before the
    /// append and `pending` is the head after the appended audit entry.
    Pending {
        /// Last known committed audit head before the pending append.
        committed: AuditHead,
        /// Expected audit head after the pending append.
        pending: AuditHead,
    },
}

/// Env var: if set, points at a file holding the pepper bytes.
///
/// This is a v0.1 escape hatch (also the spec'd Linux fallback) for
/// environments where the OS keychain is not available - headless
/// servers, CI runners, dev sandboxes that cannot prompt for keychain
/// authorization. The file is read with `0600` mode requirements
/// **enforced** on read; refusing to load a world-readable pepper file
/// is intentional. Generation is on-demand: if the file does not exist,
/// a fresh 32-byte pepper is written there with mode `0600`.
///
/// This is documented as **insecure relative to the OS keychain** -
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

/// macOS Security Framework `OSStatus` for `errSecItemNotFound`.
///
/// This is the ONLY `OSStatus` we treat as "no pepper exists yet, create one".
/// Every other status - `errSecAuthFailed` (-25293) post-sleep transient,
/// `errSecInteractionNotAllowed` (-25308) locked-headless, `errSecUserCanceled`
/// (-128), etc. - must propagate so cloakd does not regenerate-and-overwrite a
/// valid pepper (which would brick the vault). The same constant gates the
/// rollback-counter read path.
#[cfg(target_os = "macos")]
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

/// Decide, from a Security Framework `OSStatus`, whether a `get_generic_password`
/// failure means "no item exists" (safe to create) versus any other condition
/// (must propagate). Extracted for unit testing.
#[cfg(target_os = "macos")]
fn is_item_not_found(code: i32) -> bool {
    code == ERR_SEC_ITEM_NOT_FOUND
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
        Err(e) => {
            // `errSecItemNotFound` (-25300) is the legitimate first-install
            // signal - there is no pepper yet, so we generate and store one.
            //
            // ALL OTHER OSStatus values must propagate. In particular:
            //   - `errSecAuthFailed` (-25293): post-sleep transient, the
            //     keychain ACL refused the read for a moment.
            //   - `errSecInteractionNotAllowed` (-25308): keychain locked,
            //     no UI available (cloakd running headless).
            //   - `errSecUserCanceled` (-128): user dismissed the unlock
            //     prompt.
            // Treating any of these as "missing" would call
            // `set_generic_password`, which OVERWRITES the existing pepper
            // and permanently bricks the user's vault (the master-key wrap
            // can no longer be derived). Mirror the pattern used by
            // `keychain_counter_read`.
            if is_item_not_found(e.code()) {
                let pepper = crate::crypto::aead::random_bytes(PEPPER_LEN)?;
                set_generic_password(SERVICE, ACCOUNT, &pepper)
                    .map_err(|e| Error::Keychain(format!("set_generic_password: {e}")))?;
                Ok(Secret::new(pepper))
            } else {
                Err(Error::Keychain(format!(
                    "get_generic_password({SERVICE}, {ACCOUNT}): {e}"
                )))
            }
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
// The vault file's `meta.monotonic_counter` plus a digest of the logical
// vault state are mirrored to a second OS keychain item (or, in the
// file-fallback case, a sibling file). Every vault open compares the file
// state to the mirror:
//
// - file == mirror   → ok
// - file != mirror   → rollback/mirror-integrity failure. Refuse to open
//                      with `Error::VaultRollbackDetected`.
// - mirror missing   → first run after upgrade; seed mirror from file.
//
// Order on writes: record a pending mirror transition (`old -> new`),
// commit the SQLite transaction, then finalize the committed mirror. If
// the process exits in the middle, the next open accepts exactly the old
// or new state named by the pending marker and repairs the mirror.

/// Read the rollback-counter mirror, honoring `CLOAK_PEPPER_FILE` first.
/// Returns `Ok(None)` if no mirror has been written yet (fresh install or
/// upgrade from a Cloak that didn't have the mirror).
pub fn read_keychain_counter() -> Result<Option<RollbackCounterMirror>> {
    #[cfg(any(test, feature = "test-util"))]
    if rollback_mirror_disabled() {
        return Ok(None);
    }
    if let Some(path) = std::env::var_os(PEPPER_FILE_ENV) {
        return file_counter_read(std::path::Path::new(&path));
    }
    keychain_counter_read()
}

/// Read committed or pending rollback-counter mirror state.
pub fn read_rollback_counter_mirror() -> Result<Option<RollbackCounterMirror>> {
    #[cfg(any(test, feature = "test-util"))]
    if rollback_mirror_disabled() {
        return Ok(None);
    }
    let committed = read_keychain_counter()?;
    let pending = if let Some(path) = std::env::var_os(PEPPER_FILE_ENV) {
        file_pending_counter_read(std::path::Path::new(&path))?
    } else {
        keychain_pending_counter_read()?
    };
    if let Some((committed_before, pending_after)) = pending {
        return match committed {
            Some(RollbackCounterMirror::Committed(mirror)) if mirror == pending_after => {
                Ok(Some(RollbackCounterMirror::Committed(mirror)))
            }
            Some(RollbackCounterMirror::Committed(mirror)) if mirror == committed_before => {
                Ok(Some(RollbackCounterMirror::Pending {
                    committed: committed_before,
                    pending: pending_after,
                }))
            }
            Some(RollbackCounterMirror::LegacyCounter(mirror))
                if mirror == pending_after.counter =>
            {
                Ok(Some(RollbackCounterMirror::LegacyCounter(mirror)))
            }
            Some(RollbackCounterMirror::LegacyCounter(mirror))
                if mirror == committed_before.counter =>
            {
                Ok(Some(RollbackCounterMirror::Pending {
                    committed: committed_before,
                    pending: pending_after,
                }))
            }
            Some(mirror) => Ok(Some(mirror)),
            None => Ok(Some(RollbackCounterMirror::Pending {
                committed: committed_before,
                pending: pending_after,
            })),
        };
    }
    Ok(committed)
}

/// Write the rollback-state mirror to the OS keychain (or the file fallback).
/// Mutating vault operations call this before committing their SQLite
/// transaction; any failure aborts the operation.
pub fn mirror_counter(value: RollbackState) -> Result<()> {
    #[cfg(any(test, feature = "test-util"))]
    if rollback_mirror_disabled() {
        return Ok(());
    }
    if let Some(path) = std::env::var_os(PEPPER_FILE_ENV) {
        return file_counter_write(std::path::Path::new(&path), value);
    }
    keychain_counter_write(value)
}

/// Record that a rollback-counter update is in flight.
pub fn mirror_counter_pending(committed: RollbackState, pending: RollbackState) -> Result<()> {
    #[cfg(any(test, feature = "test-util"))]
    if rollback_mirror_disabled() {
        return Ok(());
    }
    if let Some(path) = std::env::var_os(PEPPER_FILE_ENV) {
        return file_pending_counter_write(std::path::Path::new(&path), committed, pending);
    }
    keychain_pending_counter_write(committed, pending)
}

/// Clear the in-flight rollback-counter marker.
pub fn clear_counter_pending() -> Result<()> {
    #[cfg(any(test, feature = "test-util"))]
    if rollback_mirror_disabled() {
        return Ok(());
    }
    if let Some(path) = std::env::var_os(PEPPER_FILE_ENV) {
        return file_pending_counter_delete(std::path::Path::new(&path));
    }
    keychain_pending_counter_delete()
}

/// Read committed or pending audit-head anchor state.
pub fn read_audit_head_anchor() -> Result<Option<AuditHeadAnchor>> {
    #[cfg(any(test, feature = "test-util"))]
    if audit_head_anchor_disabled() {
        return Ok(None);
    }
    let committed = if let Some(path) = std::env::var_os(PEPPER_FILE_ENV) {
        file_audit_head_read(std::path::Path::new(&path))?
    } else {
        keychain_audit_head_read()?
    };
    let pending = if let Some(path) = std::env::var_os(PEPPER_FILE_ENV) {
        file_pending_audit_head_read(std::path::Path::new(&path))?
    } else {
        keychain_pending_audit_head_read()?
    };
    if let Some((committed_before, pending_after)) = pending {
        return match committed {
            Some(anchor) if anchor == pending_after => Ok(Some(AuditHeadAnchor::Committed(anchor))),
            Some(anchor) if anchor == committed_before => Ok(Some(AuditHeadAnchor::Pending {
                committed: committed_before,
                pending: pending_after,
            })),
            Some(anchor) => Ok(Some(AuditHeadAnchor::Committed(anchor))),
            None => Ok(Some(AuditHeadAnchor::Pending {
                committed: committed_before,
                pending: pending_after,
            })),
        };
    }
    Ok(committed.map(AuditHeadAnchor::Committed))
}

/// Write the committed audit-head anchor.
pub fn write_audit_head_anchor(head: AuditHead) -> Result<()> {
    #[cfg(any(test, feature = "test-util"))]
    if audit_head_anchor_disabled() {
        return Ok(());
    }
    if let Some(path) = std::env::var_os(PEPPER_FILE_ENV) {
        return file_audit_head_write(std::path::Path::new(&path), head);
    }
    keychain_audit_head_write(head)
}

/// Record that an audit-head update is in flight.
pub fn write_audit_head_pending(committed: AuditHead, pending: AuditHead) -> Result<()> {
    #[cfg(any(test, feature = "test-util"))]
    if audit_head_anchor_disabled() {
        return Ok(());
    }
    if let Some(path) = std::env::var_os(PEPPER_FILE_ENV) {
        return file_pending_audit_head_write(std::path::Path::new(&path), committed, pending);
    }
    keychain_pending_audit_head_write(committed, pending)
}

/// Clear the in-flight audit-head marker.
pub fn clear_audit_head_pending() -> Result<()> {
    #[cfg(any(test, feature = "test-util"))]
    if audit_head_anchor_disabled() {
        return Ok(());
    }
    if let Some(path) = std::env::var_os(PEPPER_FILE_ENV) {
        return file_pending_audit_head_delete(std::path::Path::new(&path));
    }
    keychain_pending_audit_head_delete()
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
/// at all - a same-UID attacker cannot disable A7 read-side rollback
/// detection by setting it in their environment.
#[cfg(any(test, feature = "test-util"))]
const DISABLE_MIRROR_ENV: &str = "CLOAK_DISABLE_ROLLBACK_MIRROR";

#[cfg(any(test, feature = "test-util"))]
fn rollback_mirror_disabled() -> bool {
    std::env::var_os(DISABLE_MIRROR_ENV)
        .map(|v| v == "1")
        .unwrap_or(false)
}

#[cfg(any(test, feature = "test-util"))]
fn audit_head_anchor_disabled() -> bool {
    std::env::var_os("CLOAK_ENABLE_AUDIT_HEAD")
        .map(|v| v != "1")
        .unwrap_or(true)
}

#[cfg(any(test, feature = "test-util"))]
pub(crate) fn audit_head_anchor_enforcement_disabled() -> bool {
    audit_head_anchor_disabled()
}

#[cfg(not(any(test, feature = "test-util")))]
pub(crate) fn audit_head_anchor_enforcement_disabled() -> bool {
    false
}

/// Encode/decode helpers.
#[cfg(test)]
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

fn encode_rollback_state(state: RollbackState) -> [u8; 40] {
    let mut out = [0u8; 40];
    out[..8].copy_from_slice(&state.counter.to_be_bytes());
    out[8..40].copy_from_slice(&state.digest);
    out
}

fn decode_rollback_state(bytes: &[u8]) -> Result<RollbackCounterMirror> {
    if bytes.len() == 8 {
        return Ok(RollbackCounterMirror::LegacyCounter(decode_counter(bytes)?));
    }
    if bytes.len() != 40 {
        return Err(Error::Keychain(format!(
            "rollback state mirror has wrong length: {} (expected 40)",
            bytes.len()
        )));
    }
    let mut counter = [0u8; 8];
    counter.copy_from_slice(&bytes[..8]);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes[8..40]);
    Ok(RollbackCounterMirror::Committed(RollbackState {
        counter: u64::from_be_bytes(counter),
        digest,
    }))
}

fn decode_committed_rollback_state(bytes: &[u8]) -> Result<RollbackState> {
    match decode_rollback_state(bytes)? {
        RollbackCounterMirror::Committed(state) => Ok(state),
        RollbackCounterMirror::LegacyCounter(counter) => Ok(RollbackState {
            counter,
            digest: [0u8; 32],
        }),
        RollbackCounterMirror::Pending { .. } => {
            unreachable!("single state decoder cannot emit pending")
        }
    }
}

fn encode_pending_counter(committed: RollbackState, pending: RollbackState) -> [u8; 88] {
    let mut out = [0u8; 88];
    out[..8].copy_from_slice(PENDING_COUNTER_MAGIC);
    out[8..48].copy_from_slice(&encode_rollback_state(committed));
    out[48..88].copy_from_slice(&encode_rollback_state(pending));
    out
}

fn decode_pending_counter(bytes: &[u8]) -> Result<(RollbackState, RollbackState)> {
    if bytes.len() == 24 && &bytes[..8] == PENDING_COUNTER_MAGIC {
        let mut committed = [0u8; 8];
        committed.copy_from_slice(&bytes[8..16]);
        let mut pending = [0u8; 8];
        pending.copy_from_slice(&bytes[16..24]);
        return Ok((
            RollbackState {
                counter: u64::from_be_bytes(committed),
                digest: [0u8; 32],
            },
            RollbackState {
                counter: u64::from_be_bytes(pending),
                digest: [0u8; 32],
            },
        ));
    }
    if bytes.len() != 88 || &bytes[..8] != PENDING_COUNTER_MAGIC {
        return Err(Error::Keychain(format!(
            "rollback pending counter has wrong format: {} bytes",
            bytes.len()
        )));
    }
    let committed = decode_committed_rollback_state(&bytes[8..48])?;
    let pending = decode_committed_rollback_state(&bytes[48..88])?;
    Ok((committed, pending))
}

fn encode_audit_head(head: AuditHead) -> [u8; 40] {
    let mut out = [0u8; 40];
    out[..8].copy_from_slice(&head.seq.to_be_bytes());
    out[8..40].copy_from_slice(&head.hash);
    out
}

fn decode_audit_head(bytes: &[u8]) -> Result<AuditHead> {
    if bytes.len() != 40 {
        return Err(Error::Keychain(format!(
            "audit head anchor has wrong length: {} (expected 40)",
            bytes.len()
        )));
    }
    let mut seq = [0u8; 8];
    seq.copy_from_slice(&bytes[..8]);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes[8..40]);
    Ok(AuditHead {
        seq: u64::from_be_bytes(seq),
        hash,
    })
}

fn encode_pending_audit_head(committed: AuditHead, pending: AuditHead) -> [u8; 88] {
    let mut out = [0u8; 88];
    out[..8].copy_from_slice(PENDING_AUDIT_HEAD_MAGIC);
    out[8..48].copy_from_slice(&encode_audit_head(committed));
    out[48..88].copy_from_slice(&encode_audit_head(pending));
    out
}

fn decode_pending_audit_head(bytes: &[u8]) -> Result<(AuditHead, AuditHead)> {
    if bytes.len() != 88 || &bytes[..8] != PENDING_AUDIT_HEAD_MAGIC {
        return Err(Error::Keychain(format!(
            "audit pending head has wrong format: {} bytes",
            bytes.len()
        )));
    }
    let committed = decode_audit_head(&bytes[8..48])?;
    let pending = decode_audit_head(&bytes[48..88])?;
    Ok((committed, pending))
}

/// Resolve the file-fallback counter path: sibling of the pepper file.
fn counter_file_path(pepper_path: &std::path::Path) -> std::path::PathBuf {
    pepper_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(ROLLBACK_COUNTER_FILENAME)
}

fn pending_counter_file_path(pepper_path: &std::path::Path) -> std::path::PathBuf {
    pepper_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(ROLLBACK_COUNTER_PENDING_FILENAME)
}

fn audit_head_file_path(pepper_path: &std::path::Path) -> std::path::PathBuf {
    pepper_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(AUDIT_HEAD_FILENAME)
}

fn pending_audit_head_file_path(pepper_path: &std::path::Path) -> std::path::PathBuf {
    pepper_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(AUDIT_HEAD_PENDING_FILENAME)
}

fn file_counter_read(pepper_path: &std::path::Path) -> Result<Option<RollbackCounterMirror>> {
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
    decode_rollback_state(&bytes).map(Some)
}

fn file_counter_write(pepper_path: &std::path::Path, value: RollbackState) -> Result<()> {
    file_write_private(
        &counter_file_path(pepper_path),
        &encode_rollback_state(value),
    )
}

fn file_pending_counter_read(
    pepper_path: &std::path::Path,
) -> Result<Option<(RollbackState, RollbackState)>> {
    let path = pending_counter_file_path(pepper_path);
    if !path.exists() {
        return Ok(None);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(&path)
            .map_err(|e| Error::Keychain(format!("stat pending counter file: {e}")))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(Error::Keychain(format!(
                "rollback pending counter file {} is world/group accessible (mode {:o}); refusing to load",
                path.display(),
                mode
            )));
        }
    }
    let bytes = std::fs::read(&path)
        .map_err(|e| Error::Keychain(format!("read pending counter file: {e}")))?;
    decode_pending_counter(&bytes).map(Some)
}

fn file_pending_counter_write(
    pepper_path: &std::path::Path,
    committed: RollbackState,
    pending: RollbackState,
) -> Result<()> {
    file_write_private(
        &pending_counter_file_path(pepper_path),
        &encode_pending_counter(committed, pending),
    )
}

fn file_pending_counter_delete(pepper_path: &std::path::Path) -> Result<()> {
    let path = pending_counter_file_path(pepper_path);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Keychain(format!("delete pending counter file: {e}"))),
    }
}

fn file_audit_head_read(pepper_path: &std::path::Path) -> Result<Option<AuditHead>> {
    let path = audit_head_file_path(pepper_path);
    let Some(bytes) = file_read_private_optional(&path, "audit head")? else {
        return Ok(None);
    };
    decode_audit_head(&bytes).map(Some)
}

fn file_audit_head_write(pepper_path: &std::path::Path, head: AuditHead) -> Result<()> {
    file_write_private(&audit_head_file_path(pepper_path), &encode_audit_head(head))
}

fn file_pending_audit_head_read(
    pepper_path: &std::path::Path,
) -> Result<Option<(AuditHead, AuditHead)>> {
    let path = pending_audit_head_file_path(pepper_path);
    let Some(bytes) = file_read_private_optional(&path, "pending audit head")? else {
        return Ok(None);
    };
    decode_pending_audit_head(&bytes).map(Some)
}

fn file_pending_audit_head_write(
    pepper_path: &std::path::Path,
    committed: AuditHead,
    pending: AuditHead,
) -> Result<()> {
    file_write_private(
        &pending_audit_head_file_path(pepper_path),
        &encode_pending_audit_head(committed, pending),
    )
}

fn file_pending_audit_head_delete(pepper_path: &std::path::Path) -> Result<()> {
    let path = pending_audit_head_file_path(pepper_path);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Keychain(format!(
            "delete pending audit head file: {e}"
        ))),
    }
}

fn file_read_private_optional(
    path: &std::path::Path,
    label: &'static str,
) -> Result<Option<Vec<u8>>> {
    if !path.exists() {
        return Ok(None);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta =
            std::fs::metadata(path).map_err(|e| Error::Keychain(format!("stat {label}: {e}")))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(Error::Keychain(format!(
                "{label} file {} is world/group accessible (mode {:o}); refusing to load",
                path.display(),
                mode
            )));
        }
    }
    let bytes =
        std::fs::read(path).map_err(|e| Error::Keychain(format!("read {label} file: {e}")))?;
    Ok(Some(bytes))
}

fn file_write_private(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

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
        f.write_all(bytes)
            .map_err(|e| Error::Keychain(format!("write counter tmp: {e}")))?;
        f.sync_all()
            .map_err(|e| Error::Keychain(format!("sync counter tmp: {e}")))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| Error::Keychain(format!("rename counter tmp: {e}")))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn keychain_counter_read() -> Result<Option<RollbackCounterMirror>> {
    use security_framework::passwords::get_generic_password;
    match get_generic_password(SERVICE, ROLLBACK_COUNTER_ACCOUNT) {
        Ok(bytes) => decode_rollback_state(&bytes).map(Some),
        Err(e) => {
            // `errSecItemNotFound` (-25300) is the "no mirror yet" signal
            // - first run after upgrade. Anything else is an error.
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
fn keychain_counter_write(value: RollbackState) -> Result<()> {
    use security_framework::passwords::set_generic_password;
    set_generic_password(
        SERVICE,
        ROLLBACK_COUNTER_ACCOUNT,
        &encode_rollback_state(value),
    )
    .map_err(|e| Error::Keychain(format!("set_generic_password (rollback counter): {e}")))
}

#[cfg(target_os = "macos")]
fn keychain_pending_counter_read() -> Result<Option<(RollbackState, RollbackState)>> {
    use security_framework::passwords::get_generic_password;
    match get_generic_password(SERVICE, ROLLBACK_COUNTER_PENDING_ACCOUNT) {
        Ok(bytes) => decode_pending_counter(&bytes).map(Some),
        Err(e) => {
            if e.code() == -25300 {
                Ok(None)
            } else {
                Err(Error::Keychain(format!(
                    "get_generic_password (rollback pending counter): {e}"
                )))
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn keychain_pending_counter_write(committed: RollbackState, pending: RollbackState) -> Result<()> {
    use security_framework::passwords::set_generic_password;
    set_generic_password(
        SERVICE,
        ROLLBACK_COUNTER_PENDING_ACCOUNT,
        &encode_pending_counter(committed, pending),
    )
    .map_err(|e| {
        Error::Keychain(format!(
            "set_generic_password (rollback pending counter): {e}"
        ))
    })
}

#[cfg(target_os = "macos")]
fn keychain_pending_counter_delete() -> Result<()> {
    use security_framework::passwords::delete_generic_password;
    match delete_generic_password(SERVICE, ROLLBACK_COUNTER_PENDING_ACCOUNT) {
        Ok(()) => Ok(()),
        Err(e) => {
            if e.code() == -25300 {
                Ok(())
            } else {
                Err(Error::Keychain(format!(
                    "delete_generic_password (rollback pending counter): {e}"
                )))
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn keychain_audit_head_read() -> Result<Option<AuditHead>> {
    use security_framework::passwords::get_generic_password;
    match get_generic_password(SERVICE, AUDIT_HEAD_ACCOUNT) {
        Ok(bytes) => decode_audit_head(&bytes).map(Some),
        Err(e) => {
            if e.code() == -25300 {
                Ok(None)
            } else {
                Err(Error::Keychain(format!(
                    "get_generic_password (audit head): {e}"
                )))
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn keychain_audit_head_write(head: AuditHead) -> Result<()> {
    use security_framework::passwords::set_generic_password;
    set_generic_password(SERVICE, AUDIT_HEAD_ACCOUNT, &encode_audit_head(head))
        .map_err(|e| Error::Keychain(format!("set_generic_password (audit head): {e}")))
}

#[cfg(target_os = "macos")]
fn keychain_pending_audit_head_read() -> Result<Option<(AuditHead, AuditHead)>> {
    use security_framework::passwords::get_generic_password;
    match get_generic_password(SERVICE, AUDIT_HEAD_PENDING_ACCOUNT) {
        Ok(bytes) => decode_pending_audit_head(&bytes).map(Some),
        Err(e) => {
            if e.code() == -25300 {
                Ok(None)
            } else {
                Err(Error::Keychain(format!(
                    "get_generic_password (pending audit head): {e}"
                )))
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn keychain_pending_audit_head_write(committed: AuditHead, pending: AuditHead) -> Result<()> {
    use security_framework::passwords::set_generic_password;
    set_generic_password(
        SERVICE,
        AUDIT_HEAD_PENDING_ACCOUNT,
        &encode_pending_audit_head(committed, pending),
    )
    .map_err(|e| Error::Keychain(format!("set_generic_password (pending audit head): {e}")))
}

#[cfg(target_os = "macos")]
fn keychain_pending_audit_head_delete() -> Result<()> {
    use security_framework::passwords::delete_generic_password;
    match delete_generic_password(SERVICE, AUDIT_HEAD_PENDING_ACCOUNT) {
        Ok(()) => Ok(()),
        Err(e) => {
            if e.code() == -25300 {
                Ok(())
            } else {
                Err(Error::Keychain(format!(
                    "delete_generic_password (pending audit head): {e}"
                )))
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn keychain_counter_read() -> Result<Option<RollbackCounterMirror>> {
    linux_secret_service::counter_read()
}

#[cfg(target_os = "linux")]
fn keychain_counter_write(value: RollbackState) -> Result<()> {
    linux_secret_service::counter_write(value)
}

#[cfg(target_os = "linux")]
fn keychain_pending_counter_read() -> Result<Option<(RollbackState, RollbackState)>> {
    linux_secret_service::pending_counter_read()
}

#[cfg(target_os = "linux")]
fn keychain_pending_counter_write(committed: RollbackState, pending: RollbackState) -> Result<()> {
    linux_secret_service::pending_counter_write(committed, pending)
}

#[cfg(target_os = "linux")]
fn keychain_pending_counter_delete() -> Result<()> {
    linux_secret_service::pending_counter_delete()
}

#[cfg(target_os = "linux")]
fn keychain_audit_head_read() -> Result<Option<AuditHead>> {
    linux_secret_service::audit_head_read()
}

#[cfg(target_os = "linux")]
fn keychain_audit_head_write(head: AuditHead) -> Result<()> {
    linux_secret_service::audit_head_write(head)
}

#[cfg(target_os = "linux")]
fn keychain_pending_audit_head_read() -> Result<Option<(AuditHead, AuditHead)>> {
    linux_secret_service::pending_audit_head_read()
}

#[cfg(target_os = "linux")]
fn keychain_pending_audit_head_write(committed: AuditHead, pending: AuditHead) -> Result<()> {
    linux_secret_service::pending_audit_head_write(committed, pending)
}

#[cfg(target_os = "linux")]
fn keychain_pending_audit_head_delete() -> Result<()> {
    linux_secret_service::pending_audit_head_delete()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn keychain_counter_read() -> Result<Option<RollbackCounterMirror>> {
    Err(Error::Keychain(
        "OS keychain unsupported on this platform in v1.0; set CLOAK_PEPPER_FILE to use a file-backed rollback counter".to_string(),
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn keychain_counter_write(_value: RollbackState) -> Result<()> {
    Err(Error::Keychain(
        "OS keychain unsupported on this platform in v1.0; set CLOAK_PEPPER_FILE to use a file-backed rollback counter".to_string(),
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn keychain_pending_counter_read() -> Result<Option<(RollbackState, RollbackState)>> {
    Err(Error::Keychain(
        "OS keychain unsupported on this platform in v1.0; set CLOAK_PEPPER_FILE to use a file-backed rollback counter".to_string(),
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn keychain_pending_counter_write(
    _committed: RollbackState,
    _pending: RollbackState,
) -> Result<()> {
    Err(Error::Keychain(
        "OS keychain unsupported on this platform in v1.0; set CLOAK_PEPPER_FILE to use a file-backed rollback counter".to_string(),
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn keychain_pending_counter_delete() -> Result<()> {
    Err(Error::Keychain(
        "OS keychain unsupported on this platform in v1.0; set CLOAK_PEPPER_FILE to use a file-backed rollback counter".to_string(),
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn keychain_audit_head_read() -> Result<Option<AuditHead>> {
    Err(Error::Keychain(
        "OS keychain unsupported on this platform in v1.0; set CLOAK_PEPPER_FILE to use a file-backed audit head".to_string(),
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn keychain_audit_head_write(_head: AuditHead) -> Result<()> {
    Err(Error::Keychain(
        "OS keychain unsupported on this platform in v1.0; set CLOAK_PEPPER_FILE to use a file-backed audit head".to_string(),
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn keychain_pending_audit_head_read() -> Result<Option<(AuditHead, AuditHead)>> {
    Err(Error::Keychain(
        "OS keychain unsupported on this platform in v1.0; set CLOAK_PEPPER_FILE to use a file-backed audit head".to_string(),
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn keychain_pending_audit_head_write(_committed: AuditHead, _pending: AuditHead) -> Result<()> {
    Err(Error::Keychain(
        "OS keychain unsupported on this platform in v1.0; set CLOAK_PEPPER_FILE to use a file-backed audit head".to_string(),
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn keychain_pending_audit_head_delete() -> Result<()> {
    Err(Error::Keychain(
        "OS keychain unsupported on this platform in v1.0; set CLOAK_PEPPER_FILE to use a file-backed audit head".to_string(),
    ))
}

/// Delete the rollback-counter mirror item. Used by tests and `cloak destroy`.
#[cfg(target_os = "macos")]
pub fn delete_rollback_counter() -> Result<()> {
    use security_framework::passwords::delete_generic_password;
    match delete_generic_password(SERVICE, ROLLBACK_COUNTER_ACCOUNT) {
        Ok(()) => keychain_pending_counter_delete(),
        // -25300 == errSecItemNotFound: nothing to delete is success.
        Err(e) => {
            if e.code() == -25300 {
                keychain_pending_counter_delete()
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
    linux_secret_service::counter_delete()?;
    linux_secret_service::pending_counter_delete()
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
    use super::{
        decode_audit_head, decode_pending_audit_head, decode_pending_counter,
        decode_rollback_state, encode_audit_head, encode_pending_audit_head,
        encode_pending_counter, encode_rollback_state, AuditHead, RollbackCounterMirror,
        RollbackState,
    };
    use super::{
        ACCOUNT, AUDIT_HEAD_ACCOUNT, AUDIT_HEAD_PENDING_ACCOUNT, PEPPER_LEN,
        ROLLBACK_COUNTER_ACCOUNT, ROLLBACK_COUNTER_PENDING_ACCOUNT, SERVICE,
    };
    use crate::crypto::Secret;
    use crate::error::{Error, Result};
    use secret_service::blocking::{Collection, SecretService};
    use secret_service::EncryptionType;
    use std::collections::HashMap;

    /// Item label shown in keyring UIs (e.g. seahorse).
    const ITEM_LABEL: &str = "Cloak vault pepper";
    /// Item label for the rollback-counter mirror.
    const COUNTER_LABEL: &str = "Cloak vault rollback counter";
    /// Item label for the pending rollback-counter mirror transition.
    const PENDING_COUNTER_LABEL: &str = "Cloak vault rollback counter pending update";
    /// Item label for the audit-head anchor.
    const AUDIT_HEAD_LABEL: &str = "Cloak audit log head";
    /// Item label for the pending audit-head update.
    const PENDING_AUDIT_HEAD_LABEL: &str = "Cloak audit log head pending update";
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
    /// then `login`. If both refuse to unlock - which is what happens on
    /// a headless SSH session with no agent - surface a typed error.
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

    /// Counter-mirror search attributes - same `service`, distinct
    /// `account` so the pepper item is never accidentally read or
    /// overwritten.
    fn counter_attrs() -> HashMap<&'static str, &'static str> {
        let mut m = HashMap::new();
        m.insert("service", SERVICE);
        m.insert("account", ROLLBACK_COUNTER_ACCOUNT);
        m
    }

    fn pending_counter_attrs() -> HashMap<&'static str, &'static str> {
        let mut m = HashMap::new();
        m.insert("service", SERVICE);
        m.insert("account", ROLLBACK_COUNTER_PENDING_ACCOUNT);
        m
    }

    fn audit_head_attrs() -> HashMap<&'static str, &'static str> {
        let mut m = HashMap::new();
        m.insert("service", SERVICE);
        m.insert("account", AUDIT_HEAD_ACCOUNT);
        m
    }

    fn pending_audit_head_attrs() -> HashMap<&'static str, &'static str> {
        let mut m = HashMap::new();
        m.insert("service", SERVICE);
        m.insert("account", AUDIT_HEAD_PENDING_ACCOUNT);
        m
    }

    pub(super) fn counter_read() -> Result<Option<RollbackCounterMirror>> {
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
                decode_rollback_state(&bytes).map(Some)
            }
            None => Ok(None),
        }
    }

    pub(super) fn counter_write(value: RollbackState) -> Result<()> {
        let ss = connect()?;
        let collection = unlocked_collection(&ss)?;
        collection
            .create_item(
                COUNTER_LABEL,
                counter_attrs(),
                &encode_rollback_state(value),
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

    pub(super) fn pending_counter_read() -> Result<Option<(RollbackState, RollbackState)>> {
        let ss = connect()?;
        let search = ss
            .search_items(pending_counter_attrs())
            .map_err(dbus_unavailable)?;
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
                decode_pending_counter(&bytes).map(Some)
            }
            None => Ok(None),
        }
    }

    pub(super) fn pending_counter_write(
        committed: RollbackState,
        pending: RollbackState,
    ) -> Result<()> {
        let ss = connect()?;
        let collection = unlocked_collection(&ss)?;
        collection
            .create_item(
                PENDING_COUNTER_LABEL,
                pending_counter_attrs(),
                &encode_pending_counter(committed, pending),
                /* replace = */ true,
                CONTENT_TYPE,
            )
            .map_err(dbus_unavailable)?;
        Ok(())
    }

    pub(super) fn pending_counter_delete() -> Result<()> {
        let ss = connect()?;
        let search = ss
            .search_items(pending_counter_attrs())
            .map_err(dbus_unavailable)?;
        for item in search.unlocked.into_iter().chain(search.locked) {
            let _ = item.unlock();
            item.delete().map_err(dbus_unavailable)?;
        }
        Ok(())
    }

    pub(super) fn audit_head_read() -> Result<Option<AuditHead>> {
        let ss = connect()?;
        let search = ss
            .search_items(audit_head_attrs())
            .map_err(dbus_unavailable)?;
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
                decode_audit_head(&bytes).map(Some)
            }
            None => Ok(None),
        }
    }

    pub(super) fn audit_head_write(head: AuditHead) -> Result<()> {
        let ss = connect()?;
        let collection = unlocked_collection(&ss)?;
        collection
            .create_item(
                AUDIT_HEAD_LABEL,
                audit_head_attrs(),
                &encode_audit_head(head),
                /* replace = */ true,
                CONTENT_TYPE,
            )
            .map_err(dbus_unavailable)?;
        Ok(())
    }

    pub(super) fn pending_audit_head_read() -> Result<Option<(AuditHead, AuditHead)>> {
        let ss = connect()?;
        let search = ss
            .search_items(pending_audit_head_attrs())
            .map_err(dbus_unavailable)?;
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
                decode_pending_audit_head(&bytes).map(Some)
            }
            None => Ok(None),
        }
    }

    pub(super) fn pending_audit_head_write(committed: AuditHead, pending: AuditHead) -> Result<()> {
        let ss = connect()?;
        let collection = unlocked_collection(&ss)?;
        collection
            .create_item(
                PENDING_AUDIT_HEAD_LABEL,
                pending_audit_head_attrs(),
                &encode_pending_audit_head(committed, pending),
                /* replace = */ true,
                CONTENT_TYPE,
            )
            .map_err(dbus_unavailable)?;
        Ok(())
    }

    pub(super) fn pending_audit_head_delete() -> Result<()> {
        let ss = connect()?;
        let search = ss
            .search_items(pending_audit_head_attrs())
            .map_err(dbus_unavailable)?;
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
        //!   to set `CLOAK_PEPPER_FILE`. This test is gate-free - it
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
    fn rollback_state_encode_decode_roundtrip() {
        let state = RollbackState {
            counter: 42,
            digest: [7u8; 32],
        };
        let bytes = encode_rollback_state(state);
        assert_eq!(bytes.len(), 40);
        assert_eq!(
            decode_rollback_state(&bytes).unwrap(),
            RollbackCounterMirror::Committed(state)
        );
    }

    #[test]
    fn rollback_state_decode_accepts_legacy_counter() {
        let bytes = encode_counter(42);
        assert_eq!(
            decode_rollback_state(&bytes).unwrap(),
            RollbackCounterMirror::LegacyCounter(42)
        );
    }

    #[test]
    fn pending_rollback_state_encode_decode_roundtrip() {
        let committed = RollbackState {
            counter: 2,
            digest: [2u8; 32],
        };
        let pending = RollbackState {
            counter: 3,
            digest: [3u8; 32],
        };
        let bytes = encode_pending_counter(committed, pending);
        assert_eq!(bytes.len(), 88);
        assert_eq!(
            decode_pending_counter(&bytes).unwrap(),
            (committed, pending)
        );
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert!(matches!(decode_counter(&[]), Err(Error::Keychain(_))));
        assert!(matches!(decode_counter(&[0u8; 7]), Err(Error::Keychain(_))));
        assert!(matches!(decode_counter(&[0u8; 9]), Err(Error::Keychain(_))));
        assert!(matches!(
            decode_rollback_state(&[0u8; 39]),
            Err(Error::Keychain(_))
        ));
    }

    #[test]
    fn file_counter_write_then_read_roundtrip() {
        let dir = TempDir::new().unwrap();
        let pepper = dir.path().join("pepper");
        let first = RollbackState {
            counter: 12345,
            digest: [1u8; 32],
        };
        let second = RollbackState {
            counter: 99,
            digest: [2u8; 32],
        };
        // No counter file yet → read returns Ok(None).
        assert!(matches!(file_counter_read(&pepper), Ok(None)));
        // Write, read back.
        file_counter_write(&pepper, first).unwrap();
        assert_eq!(
            file_counter_read(&pepper).unwrap(),
            Some(RollbackCounterMirror::Committed(first))
        );
        // Overwrite with a new value.
        file_counter_write(&pepper, second).unwrap();
        assert_eq!(
            file_counter_read(&pepper).unwrap(),
            Some(RollbackCounterMirror::Committed(second))
        );
    }

    #[cfg(unix)]
    #[test]
    fn file_counter_rejects_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let pepper = dir.path().join("pepper");
        file_counter_write(
            &pepper,
            RollbackState {
                counter: 7,
                digest: [7u8; 32],
            },
        )
        .unwrap();
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

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    //! macOS keychain pepper-read classification tests.
    //!
    //! Background: a previous `Err(_) => create new pepper` arm in
    //! [`keychain_pepper`] swallowed every Security Framework error,
    //! including `errSecAuthFailed` (-25293) - a transient that fires
    //! routinely after a wake-from-sleep - and called
    //! `set_generic_password`, which **overwrites** the existing pepper.
    //! That permanently bricks the vault (the master-key wrap can no
    //! longer be derived). v1.0 BLOCKER fix.
    //!
    //! Reproducing the original bug end-to-end requires standing up a
    //! real Security Framework ACL that fails authentication on demand,
    //! which is impractical from a unit test (the SF `Error` type cannot
    //! be constructed from user code). Instead we unit-test the
    //! classification predicate that gates the regenerate-and-overwrite
    //! path, plus an `#[ignore]`d cold-start integration test that hits
    //! the real keychain (mirrors the Linux-side test gating).
    //!
    //! Manual reproduction of the original bug for posterity:
    //!   1. Open vault on a Mac.
    //!   2. `sudo pmset sleepnow`; wake.
    //!   3. Within ~2s, run a cloakd op that re-reads the pepper.
    //!   4. Pre-fix: `Err(errSecAuthFailed)` → silently overwrites the
    //!      pepper item; subsequent unlocks fail with bad-tag AEAD errors.
    //!   5. Post-fix: error propagates as `Error::Keychain` and the
    //!      pepper is preserved; retry succeeds once the keychain
    //!      transient clears.
    use super::*;

    /// `errSecItemNotFound` (-25300) is the ONLY status that authorises
    /// the regenerate-and-overwrite branch.
    #[test]
    fn item_not_found_classified_as_missing() {
        assert!(is_item_not_found(-25300));
    }

    /// Every other Security Framework status that has been observed in
    /// the field MUST NOT classify as missing - otherwise cloakd will
    /// regenerate the pepper and brick the vault.
    #[test]
    fn transient_and_locked_errors_are_not_missing() {
        // errSecAuthFailed - post-sleep transient (the original bug).
        assert!(!is_item_not_found(-25293));
        // errSecInteractionNotAllowed - locked keychain, no UI.
        assert!(!is_item_not_found(-25308));
        // errSecUserCanceled - user dismissed unlock prompt.
        assert!(!is_item_not_found(-128));
        // errSecMissingEntitlement - sandbox/entitlement misconfig.
        assert!(!is_item_not_found(-34018));
        // errSecBadReq - generic bad-request.
        assert!(!is_item_not_found(-909));
        // 0 ("no error") clearly isn't a missing item either.
        assert!(!is_item_not_found(0));
    }

    /// Cold-start: with no pepper present, `keychain_pepper` should
    /// create a 32-byte pepper and a second call should return the same
    /// bytes. Gated like the Linux Secret Service tests so it never
    /// runs unattended in CI (it would prompt for keychain access and
    /// pollute the developer's login keychain).
    #[test]
    #[ignore = "touches the real macOS login keychain; gate with RUN_MACOS_KEYCHAIN_TEST=1"]
    fn missing_item_creates() {
        if std::env::var_os("RUN_MACOS_KEYCHAIN_TEST").is_none() {
            return;
        }
        let _ = delete_pepper();
        let p1 = keychain_pepper().expect("create on miss");
        assert_eq!(p1.expose_secret().len(), PEPPER_LEN);
        let p2 = keychain_pepper().expect("hit on second call");
        assert_eq!(p1.expose_secret(), p2.expose_secret());
        let _ = delete_pepper();
    }
}
