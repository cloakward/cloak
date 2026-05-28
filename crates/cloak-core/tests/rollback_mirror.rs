//! End-to-end tests for the read-side rollback detection.
//!
//! These tests exercise the keychain rollback-counter mirror via the
//! `CLOAK_PEPPER_FILE` file fallback. Each test:
//!
//! 1. Sets `CLOAK_PEPPER_FILE` to a tempdir-relative path so both the
//!    pepper and the rollback-counter mirror live next to the vault
//!    (the production headless / CI fallback path).
//! 2. Pokes a `MetaRow` straight into the SQLite store via the public
//!    `SqliteStore` API rather than calling `Vault::initialize` —
//!    avoiding the real Argon2id autotune and any keychain ACL prompt.
//! 3. Invokes `Vault::open_or_create` and asserts the documented
//!    behaviour: equality is silent, any mismatch after a mirror exists
//!    is rejected with `Error::VaultRollbackDetected`, and a missing
//!    mirror seeds itself from the file.
//!
//! Each test is its own integration-test binary, so the env-var
//! mutation in one test cannot affect another. Within a single binary
//! the tests are serialized via a `Mutex` because Cargo otherwise runs
//! them on parallel threads of the same process.
//!
//! NOTE: these tests deliberately do NOT set
//! `CLOAK_DISABLE_ROLLBACK_MIRROR` — that knob is the cloak-core unit
//! tests' hermetic shortcut, and would defeat the purpose here.

use std::path::Path;
use std::sync::Mutex;

use cloak_core::store::{MetaRow, SqliteStore};
use cloak_core::vault::Vault;
use cloak_core::Error;

/// Serialise tests that mutate process-global env vars.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn set_pepper_file(path: &Path) {
    // SAFETY: required by std 1.84+ for env mutation. We hold ENV_LOCK
    // across both the mutation and the operation that reads the var,
    // so no parallel test in this binary can observe a torn state.
    unsafe {
        std::env::set_var("CLOAK_PEPPER_FILE", path);
    }
}

/// Seed (or rewind) an initialized vault file to the given monotonic
/// counter. Skips `Vault::initialize` so we don't pay for Argon2id
/// autotune and don't talk to the real OS keychain. If a meta row
/// already exists we drop it and reinsert at the requested counter
/// (the file's `bump_counter` would refuse a backwards move, which is
/// exactly the write-side defense; we're simulating an attacker who
/// replaced the file out-of-band, so we bypass it).
fn seed_vault(path: &Path, counter: u64) {
    let store = SqliteStore::open(path).expect("open store");
    store
        .conn()
        .execute("DELETE FROM meta WHERE id = 1", [])
        .expect("clear meta");
    let meta = MetaRow {
        format_version: 1,
        salt: [0x55u8; 16],
        // PHC string is a well-formed Argon2id encoding; we never
        // derive against it here.
        kdf_phc: "$argon2id$v=19$m=8192,t=1,p=1$\
            VVVVVVVVVVVVVVVVVVVVVQ$\
            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            .to_string(),
        wrap_nonce: [0u8; 24],
        wrap_aead: vec![0u8; 48],
        monotonic_counter: counter,
        // BIP-39 recovery columns (added in v1.0 by PR #69) are nullable
        // so older vaults continue to open. This test never exercises
        // the recovery path, so leave them empty.
        recovery_format: None,
        recovery_wrap_nonce: None,
        recovery_wrap_aead: None,
        created_at: "2026-01-01T00:00:00+00:00".to_string(),
    };
    store.set_meta(&meta).expect("set meta");
}

/// Acquire ENV_LOCK, recovering from poison so a panic in one test
/// doesn't cascade through the rest of the binary.
fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

fn read_counter_file(pepper_path: &Path) -> Option<u64> {
    let counter_path = pepper_path.parent().unwrap().join("rollback-counter");
    if !counter_path.exists() {
        return None;
    }
    let bytes = std::fs::read(&counter_path).expect("read counter file");
    assert_eq!(bytes.len(), 8, "counter file must be 8 bytes");
    let mut a = [0u8; 8];
    a.copy_from_slice(&bytes);
    Some(u64::from_be_bytes(a))
}

#[test]
fn missing_mirror_seeds_from_file_on_first_open() {
    let _g = lock_env();
    let dir = tempfile::tempdir().unwrap();
    let pepper = dir.path().join("pepper");
    let vault_path = dir.path().join("vault.cloak");
    set_pepper_file(&pepper);

    seed_vault(&vault_path, 7);

    // No mirror file exists yet → first open should seed from the
    // file counter and succeed.
    let _v = Vault::open_or_create(&vault_path).expect("open should seed mirror");

    assert_eq!(
        read_counter_file(&pepper),
        Some(7),
        "mirror should have been seeded from the vault file counter"
    );
}

#[test]
fn rollback_detected_when_file_counter_lower_than_mirror() {
    let _g = lock_env();
    let dir = tempfile::tempdir().unwrap();
    let pepper = dir.path().join("pepper");
    let vault_path = dir.path().join("vault.cloak");
    set_pepper_file(&pepper);

    // Stage 1: simulate a vault that has been bumped to counter=10
    // and whose mirror is in sync.
    seed_vault(&vault_path, 10);
    {
        let _v = Vault::open_or_create(&vault_path).expect("seed mirror to 10");
    }
    assert_eq!(read_counter_file(&pepper), Some(10));

    // Stage 2: attacker rolls the vault back to a stale snapshot
    // with counter=5 (mirror still says 10). Open must refuse.
    seed_vault(&vault_path, 5);
    match Vault::open_or_create(&vault_path) {
        Ok(_) => panic!("rollback must be rejected"),
        Err(Error::VaultRollbackDetected) => {}
        Err(e) => panic!("expected VaultRollbackDetected, got {e:?}"),
    }
}

#[test]
fn file_counter_greater_than_mirror_is_rejected() {
    let _g = lock_env();
    let dir = tempfile::tempdir().unwrap();
    let pepper = dir.path().join("pepper");
    let vault_path = dir.path().join("vault.cloak");
    set_pepper_file(&pepper);

    // Stage 1: vault and mirror both at counter=3.
    seed_vault(&vault_path, 3);
    {
        let _v = Vault::open_or_create(&vault_path).expect("seed");
    }
    assert_eq!(read_counter_file(&pepper), Some(3));

    // Stage 2: the vault file counter jumps to 9 while the mirror is
    // still at 3. Even though the file counter is greater, accepting it
    // would let an attacker replay an older vault snapshot and manually
    // bump its counter, so open must refuse.
    seed_vault(&vault_path, 9);
    match Vault::open_or_create(&vault_path) {
        Ok(_) => panic!("counter mismatch must be rejected"),
        Err(Error::VaultRollbackDetected) => {}
        Err(e) => panic!("expected VaultRollbackDetected, got {e:?}"),
    }
    assert_eq!(read_counter_file(&pepper), Some(3));
}

#[test]
fn equality_is_silent_no_op() {
    let _g = lock_env();
    let dir = tempfile::tempdir().unwrap();
    let pepper = dir.path().join("pepper");
    let vault_path = dir.path().join("vault.cloak");
    set_pepper_file(&pepper);

    seed_vault(&vault_path, 4);
    {
        let _v = Vault::open_or_create(&vault_path).expect("seed");
    }
    // Capture the mirror file's mtime, reopen, and verify the file
    // wasn't rewritten when there's no work to do.
    let counter_path = pepper.parent().unwrap().join("rollback-counter");
    let mtime_before = std::fs::metadata(&counter_path)
        .unwrap()
        .modified()
        .unwrap();
    // Sleep one second so any rewrite would advance mtime visibly on
    // every reasonable filesystem.
    std::thread::sleep(std::time::Duration::from_secs(1));
    {
        let _v = Vault::open_or_create(&vault_path).expect("equality reopen");
    }
    let mtime_after = std::fs::metadata(&counter_path)
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(
        mtime_before, mtime_after,
        "equality path must not rewrite the mirror file"
    );
}

#[test]
fn out_of_band_write_without_mirror_bump_is_rejected() {
    let _g = lock_env();
    let dir = tempfile::tempdir().unwrap();
    let pepper = dir.path().join("pepper");
    let vault_path = dir.path().join("vault.cloak");
    set_pepper_file(&pepper);

    // Bring up a vault with counter=1 and a synced mirror.
    seed_vault(&vault_path, 1);
    let v = Vault::open_or_create(&vault_path).expect("seed");
    assert_eq!(read_counter_file(&pepper), Some(1));

    // Simulate an out-of-band write that only advances the file counter.
    // The vault must not treat that as legitimate unless the mirror was
    // advanced by the trusted write path too.
    drop(v);
    let store = SqliteStore::open(&vault_path).unwrap();
    store.bump_counter(2).unwrap();
    drop(store);

    match Vault::open_or_create(&vault_path) {
        Ok(_) => panic!("mismatch must be rejected"),
        Err(Error::VaultRollbackDetected) => {}
        Err(e) => panic!("expected VaultRollbackDetected, got {e:?}"),
    }
    assert_eq!(
        read_counter_file(&pepper),
        Some(1),
        "mirror must not be refreshed from an out-of-band file bump"
    );
}
