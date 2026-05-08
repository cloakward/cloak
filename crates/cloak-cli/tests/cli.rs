//! End-to-end tests for the `cloak` binary.
//!
//! These run the compiled `cloak` binary via [`assert_cmd`] against a
//! tempdir vault. The `CLOAK_PASSPHRASE` env var bypasses the
//! interactive passphrase prompt — it's a test-only escape hatch
//! documented in [`cloak_cli::prompt`]. We never go through Touch ID;
//! `--no-biometric` short-circuits that.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;

const TEST_PASSPHRASE: &str = "REDACTED-test-passphrase";

/// Build a `cloak` command rooted at a fresh tempdir vault. The caller
/// owns the `TempDir` so the vault file is cleaned up at end-of-test.
///
/// The CLI workflow sets `CLOAK_PEPPER_FILE: target/cloak-ci-pepper`
/// once per job, but cargo runs these tests in parallel — so multiple
/// `cloak init` invocations race on `OpenOptions::create_new(true)`
/// for that single shared file and one of them fails with
/// `File exists (os error 17)`. Override the env var per test with a
/// path inside the test's own tempdir so each test gets an isolated
/// pepper file. This also matches the production deployment posture
/// (one pepper file per cloakd instance).
fn cloak(dir: &TempDir) -> (Command, PathBuf) {
    let path = dir.path().join("vault.cloak");
    let pepper = dir.path().join("pepper");
    let mut cmd = Command::cargo_bin("cloak").expect("binary built");
    cmd.arg("--vault").arg(&path).arg("--no-biometric");
    cmd.env("CLOAK_PASSPHRASE", TEST_PASSPHRASE);
    cmd.env("CLOAK_PEPPER_FILE", &pepper);
    // Tell tracing-subscriber to be quiet during tests.
    cmd.env("RUST_LOG", "off");
    // Disable the OS-keychain rollback-counter mirror in this child
    // process. Each CLI test creates a fresh vault file in its own
    // tempdir; if a prior test run left a higher counter in the
    // shared OS keychain, `cloak init` would refuse to open the
    // newly-created (counter=1) vault as a rollback. The mirror's
    // production behaviour is covered by
    // `crates/cloak-core/tests/rollback_mirror.rs`.
    cmd.env("CLOAK_DISABLE_ROLLBACK_MIRROR", "1");
    (cmd, path)
}

// -------------------------------------------------------------------------
// Smoke tests for top-level flags
// -------------------------------------------------------------------------

#[test]
fn version_flag() {
    let mut cmd = Command::cargo_bin("cloak").unwrap();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"cloak \d+\.\d+\.\d+").unwrap());
}

#[test]
fn help_flag_mentions_cloak() {
    let mut cmd = Command::cargo_bin("cloak").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Cloak"));
}

#[test]
fn help_text_snapshot() {
    // The first run of this test will create a `.snap.new` file in
    // `tests/snapshots/`; reviewers run `cargo insta accept` to promote
    // it to a real snapshot. On CI we expect the committed snapshot to
    // already match.
    let mut cmd = Command::cargo_bin("cloak").unwrap();
    let output = cmd.arg("--help").output().expect("help should run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Normalize the version stamp so the snapshot is stable across bumps.
    // Keep dependencies light: a plain string replacement using the
    // version-line marker rather than pulling in the `regex` crate.
    let normalized = stdout.replace(
        &format!("cloak {}", env!("CARGO_PKG_VERSION")),
        "cloak X.Y.Z",
    );
    insta::assert_snapshot!("help_text", normalized);
}

// -------------------------------------------------------------------------
// status against an uninitialized vault
// -------------------------------------------------------------------------

#[test]
fn status_uninitialized_exits_two() {
    let dir = TempDir::new().unwrap();
    let (mut cmd, _) = cloak(&dir);
    cmd.arg("status")
        .assert()
        .code(2)
        .stdout(predicate::str::contains("uninitialized"));
}

// -------------------------------------------------------------------------
// init → status → add → list → get → rm round-trip
// -------------------------------------------------------------------------

#[test]
fn init_then_status_reports_zero_records() {
    let dir = TempDir::new().unwrap();
    let (mut init, _) = cloak(&dir);
    init.arg("init").assert().success();

    let (mut status, _) = cloak(&dir);
    status
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("records:"))
        .stdout(predicate::str::contains("0"));
}

#[test]
fn add_then_list_shows_name() {
    let dir = TempDir::new().unwrap();

    let (mut init, _) = cloak(&dir);
    init.arg("init").assert().success();

    let (mut add, _) = cloak(&dir);
    add.arg("add")
        .arg("OPENAI_API_KEY")
        .write_stdin("sk-REDACTED\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("added: OPENAI_API_KEY"));

    let (mut list, _) = cloak(&dir);
    list.arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("OPENAI_API_KEY"))
        .stdout(predicate::str::contains("api_key"));
}

#[test]
fn get_returns_metadata() {
    let dir = TempDir::new().unwrap();
    let (mut init, _) = cloak(&dir);
    init.arg("init").assert().success();

    let (mut add, _) = cloak(&dir);
    add.arg("add")
        .arg("DB_URL")
        .arg("--kind")
        .arg("db_url")
        .arg("--tag")
        .arg("prod")
        .write_stdin("postgres://REDACTED\n")
        .assert()
        .success();

    let (mut get, _) = cloak(&dir);
    get.arg("get")
        .arg("DB_URL")
        .assert()
        .success()
        .stdout(predicate::str::contains("name:"))
        .stdout(predicate::str::contains("DB_URL"))
        .stdout(predicate::str::contains("kind:"))
        .stdout(predicate::str::contains("db_url"))
        .stdout(predicate::str::contains("tags:"))
        .stdout(predicate::str::contains("prod"))
        .stdout(predicate::str::contains("version:"));
}

#[test]
fn rm_yes_removes_secret() {
    let dir = TempDir::new().unwrap();
    let (mut init, _) = cloak(&dir);
    init.arg("init").assert().success();

    let (mut add, _) = cloak(&dir);
    add.arg("add")
        .arg("TMPKEY")
        .write_stdin("v\n")
        .assert()
        .success();

    let (mut rm, _) = cloak(&dir);
    rm.arg("rm")
        .arg("TMPKEY")
        .arg("--yes")
        .assert()
        .success()
        .stdout(predicate::str::contains("removed: TMPKEY"));

    let (mut list, _) = cloak(&dir);
    list.arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("TMPKEY").not());
}

// -------------------------------------------------------------------------
// show against an uninitialized vault — no panic, non-zero exit
// -------------------------------------------------------------------------

#[test]
fn show_uninitialized_does_not_panic() {
    let dir = TempDir::new().unwrap();
    let (mut cmd, _) = cloak(&dir);
    let assertion = cmd.arg("show").arg("anything").assert();
    let output = assertion.get_output();
    assert!(
        !output.status.success(),
        "show against uninitialized vault should fail"
    );
}

// -------------------------------------------------------------------------
// list on empty vault prints "(no secrets)"
// -------------------------------------------------------------------------

#[test]
fn list_empty_vault() {
    let dir = TempDir::new().unwrap();
    let (mut init, _) = cloak(&dir);
    init.arg("init").assert().success();

    let (mut list, _) = cloak(&dir);
    list.arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("(no secrets)"));
}

// -------------------------------------------------------------------------
// completions emits non-empty bash output
// -------------------------------------------------------------------------

#[test]
fn completions_bash() {
    let mut cmd = Command::cargo_bin("cloak").unwrap();
    cmd.arg("completions")
        .arg("bash")
        .assert()
        .success()
        .stdout(predicate::str::contains("complete -F"));
}

// -------------------------------------------------------------------------
// add of a duplicate name fails
// -------------------------------------------------------------------------

#[test]
fn add_duplicate_fails() {
    let dir = TempDir::new().unwrap();
    let (mut init, _) = cloak(&dir);
    init.arg("init").assert().success();

    let (mut add1, _) = cloak(&dir);
    add1.arg("add")
        .arg("DUP")
        .write_stdin("v1\n")
        .assert()
        .success();

    let (mut add2, _) = cloak(&dir);
    add2.arg("add")
        .arg("DUP")
        .write_stdin("v2\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}
