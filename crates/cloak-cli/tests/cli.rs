//! End-to-end tests for the `cloak` binary.
//!
//! These run the compiled `cloak` binary via [`assert_cmd`] against a
//! tempdir vault. `CLOAK_UNSAFE_TEST_MODE=1` enables test-only env
//! overrides like `CLOAK_PASSPHRASE`; normal CLI use must not honor
//! those variables silently. We never go through Touch ID;
//! `--no-biometric` short-circuits that.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;

const TEST_PASSPHRASE: &str = "REDACTED-test-passphrase";
const TEST_MODE_ENV: &str = "CLOAK_UNSAFE_TEST_MODE";

/// Build a `cloak` command rooted at a fresh tempdir vault. The caller
/// owns the `TempDir` so the vault file is cleaned up at end-of-test.
///
/// The CLI workflow sets `CLOAK_PEPPER_FILE: target/cloak-ci-pepper`
/// once per job, but cargo runs these tests in parallel - so multiple
/// `cloak init` invocations race on `OpenOptions::create_new(true)`
/// for that single shared file and one of them fails with
/// `File exists (os error 17)`. Override the env var per test with a
/// path inside the test's own tempdir so each test gets an isolated
/// pepper file. This also matches the production deployment posture
/// (one pepper file per cloakd instance).
fn cloak(dir: &TempDir) -> (Command, PathBuf) {
    let path = dir.path().join("vault.cloak");
    let pepper = dir.path().join("pepper");
    let data_home = dir.path().join("data");
    std::fs::create_dir_all(&data_home).expect("create per-test data dir");
    let mut cmd = Command::cargo_bin("cloak").expect("binary built");
    cmd.arg("--vault").arg(&path).arg("--no-biometric");
    cmd.env(TEST_MODE_ENV, "1");
    cmd.env("CLOAK_PASSPHRASE", TEST_PASSPHRASE);
    cmd.env("CLOAK_PEPPER_FILE", &pepper);
    cmd.env("XDG_DATA_HOME", &data_home);
    cmd.env("HOME", dir.path());
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
    // `assert_cmd` runs the binary with no PTY, so `cloak init` would
    // refuse to print the BIP-39 mnemonic to non-TTY stdout. Opt into
    // the test-only escape hatch documented in `recovery_display`.
    cmd.env("CLOAK_ALLOW_MNEMONIC_STDOUT", "1");
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
        .write_stdin("REDACTED_TEST_OPENAI_KEY\n")
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
// show against an uninitialized vault - no panic, non-zero exit
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

#[test]
fn test_only_passphrase_env_requires_unsafe_guard() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.cloak");
    let pepper = dir.path().join("pepper");
    let mut cmd = Command::cargo_bin("cloak").unwrap();
    cmd.arg("--vault")
        .arg(&path)
        .arg("--no-biometric")
        .env("CLOAK_PASSPHRASE", TEST_PASSPHRASE)
        .env("CLOAK_PEPPER_FILE", &pepper)
        .env("CLOAK_ALLOW_MNEMONIC_STDOUT", "1")
        .env("RUST_LOG", "off")
        .arg("init")
        .assert()
        .failure()
        .stderr(predicate::str::contains(TEST_MODE_ENV));
}

// -------------------------------------------------------------------------
// .env import / export
// -------------------------------------------------------------------------

#[test]
fn dotenv_import_export_round_trips_escaped_values() {
    let dir = TempDir::new().unwrap();
    let (mut init, _) = cloak(&dir);
    init.arg("init").assert().success();

    let input = dir.path().join("input.env");
    std::fs::write(
        &input,
        "QUOTE=\"say \\\"hello\\\"\"\nBACKSLASH=\"C:\\\\tmp\\\\cloak\"\nMULTILINE=\"line one\\nline two\"\n",
    )
    .unwrap();

    let (mut import, _) = cloak(&dir);
    import.arg("import").arg(&input).assert().success();

    let output = dir.path().join("roundtrip.env");
    let (mut export, _) = cloak(&dir);
    export
        .arg("export")
        .arg(&output)
        .arg("--force")
        .assert()
        .success();
    let exported = std::fs::read_to_string(output).unwrap();
    assert!(exported.contains("QUOTE=\"say \\\"hello\\\"\"\n"));
    assert!(exported.contains("BACKSLASH=\"C:\\\\tmp\\\\cloak\"\n"));
    assert!(exported.contains("MULTILINE=\"line one\\nline two\"\n"));
}

#[test]
fn import_replace_requires_confirmation_before_deleting() {
    let dir = TempDir::new().unwrap();
    let (mut init, _) = cloak(&dir);
    init.arg("init").assert().success();

    let (mut add_keep, _) = cloak(&dir);
    add_keep
        .arg("add")
        .arg("KEEP")
        .write_stdin("old\n")
        .assert()
        .success();
    let (mut add_delete, _) = cloak(&dir);
    add_delete
        .arg("add")
        .arg("DELETE_ME")
        .write_stdin("gone\n")
        .assert()
        .success();

    let input = dir.path().join("replace.env");
    std::fs::write(&input, "KEEP=new\n").unwrap();

    let (mut replace, _) = cloak(&dir);
    replace
        .arg("import")
        .arg(&input)
        .arg("--replace")
        .assert()
        .success()
        .stdout(predicate::str::contains("cancelled"));

    let (mut list, _) = cloak(&dir);
    list.arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("DELETE_ME"));
    let (mut show_keep, _) = cloak(&dir);
    show_keep
        .arg("show")
        .arg("KEEP")
        .arg("--allow-redirect")
        .assert()
        .success()
        .stdout(predicate::str::contains("old"));

    let (mut replace_yes, _) = cloak(&dir);
    replace_yes
        .arg("import")
        .arg(&input)
        .arg("--replace")
        .arg("--yes")
        .assert()
        .success()
        .stdout(predicate::str::contains("1 removed"));

    let (mut list_after, _) = cloak(&dir);
    list_after
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("DELETE_ME").not());
    let (mut show_after, _) = cloak(&dir);
    show_after
        .arg("show")
        .arg("KEEP")
        .arg("--allow-redirect")
        .assert()
        .success()
        .stdout(predicate::str::contains("new"));
}

// -------------------------------------------------------------------------
// BIP-39 recovery seed
// -------------------------------------------------------------------------

/// Pull the 24-word phrase out of `cloak init`'s stdout. The mnemonic
/// is printed in a 4-column grid where each cell looks like ` 7. word`,
/// so we parse the grid lines and reassemble in word-index order.
fn parse_mnemonic_from_init(stdout: &str) -> String {
    use std::collections::BTreeMap;
    let mut by_idx: BTreeMap<u32, String> = BTreeMap::new();
    // Walk every whitespace-separated token. Matching tokens look like
    // "NN.", with the next non-empty token being the lowercase word.
    let tokens: Vec<&str> = stdout.split_whitespace().collect();
    let mut i = 0;
    while i + 1 < tokens.len() {
        let head = tokens[i];
        if let Some(rest) = head.strip_suffix('.') {
            if let Ok(idx) = rest.parse::<u32>() {
                if (1..=24).contains(&idx) {
                    let candidate = tokens[i + 1];
                    if !candidate.is_empty() && candidate.chars().all(|c| c.is_ascii_lowercase()) {
                        by_idx.entry(idx).or_insert_with(|| candidate.to_string());
                        i += 2;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }
    assert_eq!(by_idx.len(), 24, "expected 24 words in init stdout");
    by_idx.into_values().collect::<Vec<_>>().join(" ")
}

#[test]
fn init_prints_24_word_mnemonic_and_warning() {
    let dir = TempDir::new().unwrap();
    let (mut init, _) = cloak(&dir);
    let out = init.arg("init").output().expect("init runs");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("WRITE THESE 24 WORDS"),
        "init must surface the recovery-seed warning"
    );
    let mnemonic = parse_mnemonic_from_init(&stdout);
    assert_eq!(
        mnemonic.split_whitespace().count(),
        24,
        "init should print 24 words"
    );
}

#[test]
fn backup_verify_round_trips_mnemonic() {
    let dir = TempDir::new().unwrap();
    let (mut init, _) = cloak(&dir);
    let out = init.arg("init").output().expect("init runs");
    assert!(out.status.success());
    let mnemonic = parse_mnemonic_from_init(&String::from_utf8_lossy(&out.stdout));

    let (mut verify, _) = cloak(&dir);
    verify
        .arg("backup")
        .arg("verify")
        .env("CLOAK_MNEMONIC", &mnemonic)
        .assert()
        .success()
        .stdout(predicate::str::contains("matches this vault"));
}

#[test]
fn backup_verify_rejects_wrong_mnemonic() {
    let dir = TempDir::new().unwrap();
    let (mut init, _) = cloak(&dir);
    init.arg("init").assert().success();

    // 24 valid wordlist entries that almost certainly fail the BIP-39
    // checksum against this vault.
    let bogus = "abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon abandon";
    let (mut verify, _) = cloak(&dir);
    verify
        .arg("backup")
        .arg("verify")
        .env("CLOAK_MNEMONIC", bogus)
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid recovery mnemonic"));
}

#[test]
fn backup_verify_requires_passphrase_before_mnemonic_check() {
    let dir = TempDir::new().unwrap();
    let (mut init, _) = cloak(&dir);
    let out = init.arg("init").output().expect("init runs");
    assert!(out.status.success());
    let mnemonic = parse_mnemonic_from_init(&String::from_utf8_lossy(&out.stdout));

    let path = dir.path().join("vault.cloak");
    let pepper = dir.path().join("pepper");
    let data_root = dir.path().join("data");
    std::fs::create_dir_all(&data_root).unwrap();
    let mut verify = Command::cargo_bin("cloak").unwrap();
    verify
        .arg("--vault")
        .arg(&path)
        .arg("--no-biometric")
        .env(TEST_MODE_ENV, "1")
        .env("CLOAK_PASSPHRASE", "totally-wrong-passphrase")
        .env("CLOAK_MNEMONIC", &mnemonic)
        .env("CLOAK_PEPPER_FILE", &pepper)
        .env("CLOAK_DISABLE_ROLLBACK_MIRROR", "1")
        .env("XDG_DATA_HOME", &data_root)
        .env("HOME", dir.path())
        .env("RUST_LOG", "off")
        .arg("backup")
        .arg("verify")
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid passphrase"));
}

#[test]
fn setup_writes_init_audit_entries() {
    use std::fs;

    let dir = TempDir::new().unwrap();
    let data_root = dir.path().join("data");
    fs::create_dir_all(&data_root).unwrap();
    let path = dir.path().join("vault.cloak");
    let pepper = dir.path().join("pepper");

    let mut setup = Command::cargo_bin("cloak").unwrap();
    setup
        .arg("--vault")
        .arg(&path)
        .env(TEST_MODE_ENV, "1")
        .env("CLOAK_PASSPHRASE", TEST_PASSPHRASE)
        .env("CLOAK_PEPPER_FILE", &pepper)
        .env("CLOAK_DISABLE_ROLLBACK_MIRROR", "1")
        .env("CLOAK_ALLOW_MNEMONIC_STDOUT", "1")
        .env("XDG_DATA_HOME", &data_root)
        .env("HOME", dir.path())
        .env("RUST_LOG", "off")
        .arg("setup")
        .arg("--skip-daemon")
        .arg("--skip-clients")
        .arg("--skip-env")
        .assert()
        .success();

    let candidates = [
        data_root.join("cloak/audit.jsonl"),
        dir.path()
            .join("Library/Application Support/cloak/audit.jsonl"),
    ];
    let body = candidates
        .iter()
        .find_map(|p| fs::read_to_string(p).ok())
        .expect("setup audit file written under the test root");
    assert!(
        body.lines().any(|line| {
            line.contains(r#""tool":"cli.init""#) && line.contains(r#""result":"started""#)
        }),
        "setup should audit initialization start: {body}"
    );
    assert!(
        body.lines().any(|line| {
            line.contains(r#""tool":"cli.init""#) && line.contains(r#""result":"ok""#)
        }),
        "setup should audit initialization success: {body}"
    );
}

#[test]
fn audit_adopt_head_recovers_legacy_nonempty_log() {
    let dir = TempDir::new().unwrap();
    let data_root = dir.path().join("data");
    std::fs::create_dir_all(&data_root).unwrap();

    let (mut init, _) = cloak(&dir);
    init.env("XDG_DATA_HOME", &data_root)
        .env("HOME", dir.path())
        .arg("init")
        .assert()
        .success();

    let (mut verify_before, _) = cloak(&dir);
    verify_before
        .env("XDG_DATA_HOME", &data_root)
        .env("HOME", dir.path())
        .env("CLOAK_ENABLE_AUDIT_HEAD", "1")
        .arg("audit")
        .arg("verify")
        .assert()
        .failure()
        .stderr(predicate::str::contains("audit head anchor mismatch"));

    let (mut adopt, _) = cloak(&dir);
    adopt
        .env("XDG_DATA_HOME", &data_root)
        .env("HOME", dir.path())
        .env("CLOAK_ENABLE_AUDIT_HEAD", "1")
        .arg("audit")
        .arg("adopt-head")
        .arg("--yes")
        .assert()
        .success()
        .stdout(predicate::str::contains("audit head anchor adopted"));

    let (mut verify_after, _) = cloak(&dir);
    verify_after
        .env("XDG_DATA_HOME", &data_root)
        .env("HOME", dir.path())
        .env("CLOAK_ENABLE_AUDIT_HEAD", "1")
        .arg("audit")
        .arg("verify")
        .assert()
        .success()
        .stdout(predicate::str::contains("audit log ok"));
}

#[test]
fn unauthenticated_audit_append_does_not_seed_erased_chain() {
    let dir = TempDir::new().unwrap();
    let data_root = dir.path().join("data");
    std::fs::create_dir_all(&data_root).unwrap();

    let (mut init, _) = cloak(&dir);
    init.env("XDG_DATA_HOME", &data_root)
        .env("HOME", dir.path())
        .env("CLOAK_ENABLE_AUDIT_HEAD", "1")
        .arg("init")
        .assert()
        .success();

    let audit_candidates = [
        data_root.join("cloak/audit.jsonl"),
        dir.path()
            .join("Library/Application Support/cloak/audit.jsonl"),
    ];
    let audit_path = audit_candidates
        .iter()
        .find(|p| p.exists())
        .expect("init should create an audit log");
    std::fs::remove_file(audit_path).unwrap();
    let audit_head = dir.path().join("audit-head");
    std::fs::remove_file(&audit_head).unwrap();

    // `backup verify` appends its "started" audit entry before passphrase
    // unlock/user-presence. It must fail closed instead of re-seeding a
    // missing anchor over an erased log.
    let (mut backup_verify, _) = cloak(&dir);
    backup_verify
        .env("XDG_DATA_HOME", &data_root)
        .env("HOME", dir.path())
        .env("CLOAK_ENABLE_AUDIT_HEAD", "1")
        .arg("backup")
        .arg("verify")
        .assert()
        .failure()
        .stderr(predicate::str::contains("adopt-head"));

    assert!(
        !audit_head.exists(),
        "unauthenticated audit append must not re-create the anchor"
    );
}

#[test]
fn rollback_adopt_state_recovers_legacy_counter_mirror() {
    let dir = TempDir::new().unwrap();
    let (mut init, _) = cloak(&dir);
    init.arg("init").assert().success();

    let legacy_counter = dir.path().join("rollback-counter");
    std::fs::write(&legacy_counter, 1u64.to_be_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&legacy_counter, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let (mut list_before, _) = cloak(&dir);
    list_before
        .env_remove("CLOAK_DISABLE_ROLLBACK_MIRROR")
        .arg("list")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "legacy rollback counter mirror requires explicit adoption",
        ));

    let (mut adopt, _) = cloak(&dir);
    adopt
        .env_remove("CLOAK_DISABLE_ROLLBACK_MIRROR")
        .arg("rollback")
        .arg("adopt-state")
        .arg("--yes")
        .assert()
        .success()
        .stdout(predicate::str::contains("rollback state mirror adopted"));

    assert_eq!(std::fs::read(&legacy_counter).unwrap().len(), 40);

    let (mut list_after, _) = cloak(&dir);
    list_after
        .env_remove("CLOAK_DISABLE_ROLLBACK_MIRROR")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("(no secrets)"));
}

#[test]
fn rollback_adopt_state_requires_yes() {
    let dir = TempDir::new().unwrap();
    let (mut cmd, _) = cloak(&dir);
    cmd.arg("rollback")
        .arg("adopt-state")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "refusing to adopt rollback state without --yes",
        ));
}

#[test]
fn restore_recovers_after_passphrase_loss() {
    let dir = TempDir::new().unwrap();

    // 1. Create a vault, capture the mnemonic, store a secret.
    let (mut init, _) = cloak(&dir);
    let out = init.arg("init").output().expect("init runs");
    assert!(out.status.success());
    let mnemonic = parse_mnemonic_from_init(&String::from_utf8_lossy(&out.stdout));

    let (mut add, _) = cloak(&dir);
    add.arg("add")
        .arg("APIKEY")
        .write_stdin("super-secret-payload\n")
        .assert()
        .success();

    // 2. "Lose" the passphrase: switch CLOAK_PASSPHRASE to a new value
    //    and confirm the original is no longer accepted by `show`.
    let path = dir.path().join("vault.cloak");
    let pepper = dir.path().join("pepper");
    let data_root = dir.path().join("data");
    std::fs::create_dir_all(&data_root).unwrap();
    let mut bad_show = Command::cargo_bin("cloak").unwrap();
    bad_show
        .arg("--vault")
        .arg(&path)
        .arg("--no-biometric")
        .env(TEST_MODE_ENV, "1")
        .env("CLOAK_PASSPHRASE", "totally-different-pass")
        .env("CLOAK_PEPPER_FILE", &pepper)
        .env("CLOAK_DISABLE_ROLLBACK_MIRROR", "1")
        .env("XDG_DATA_HOME", &data_root)
        .env("HOME", dir.path())
        .env("RUST_LOG", "off")
        .arg("show")
        .arg("APIKEY")
        .arg("--allow-redirect")
        .assert()
        .failure();

    // 3. Restore using the mnemonic + a new passphrase.
    let mut restore = Command::cargo_bin("cloak").unwrap();
    restore
        .arg("--vault")
        .arg(&path)
        .arg("--no-biometric")
        .env(TEST_MODE_ENV, "1")
        .env("CLOAK_PASSPHRASE", "fresh-recovery-pass")
        .env("CLOAK_MNEMONIC", &mnemonic)
        .env("CLOAK_PEPPER_FILE", &pepper)
        .env("CLOAK_DISABLE_ROLLBACK_MIRROR", "1")
        .env("CLOAK_ALLOW_MNEMONIC_STDOUT", "1")
        .env("XDG_DATA_HOME", &data_root)
        .env("HOME", dir.path())
        .env("RUST_LOG", "off")
        .arg("restore")
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault restored"));

    // 4. The new passphrase now decrypts the original secret.
    let mut show = Command::cargo_bin("cloak").unwrap();
    show.arg("--vault")
        .arg(&path)
        .arg("--no-biometric")
        .env(TEST_MODE_ENV, "1")
        .env("CLOAK_PASSPHRASE", "fresh-recovery-pass")
        .env("CLOAK_PEPPER_FILE", &pepper)
        .env("CLOAK_DISABLE_ROLLBACK_MIRROR", "1")
        .env("XDG_DATA_HOME", &data_root)
        .env("HOME", dir.path())
        .env("RUST_LOG", "off")
        .arg("show")
        .arg("APIKEY")
        .arg("--allow-redirect")
        .assert()
        .success()
        .stdout(predicate::str::contains("super-secret-payload"));
}

#[test]
fn restore_rejects_invalid_mnemonic() {
    let dir = TempDir::new().unwrap();
    let (mut init, _) = cloak(&dir);
    init.arg("init").assert().success();

    let (mut restore, _) = cloak(&dir);
    restore
        .arg("restore")
        .env("CLOAK_MNEMONIC", "not even close to a real seed phrase")
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid recovery mnemonic"));
}

#[test]
fn restore_writes_audit_entry() {
    use std::fs;
    let dir = TempDir::new().unwrap();
    let (mut init, _) = cloak(&dir);
    let out = init.arg("init").output().expect("init runs");
    let mnemonic = parse_mnemonic_from_init(&String::from_utf8_lossy(&out.stdout));

    // Point the CLI at a controlled audit-log location via XDG_DATA_HOME
    // (cloak picks `dirs::data_dir()` which honors that on Linux; on
    // macOS we rely on the binary writing under `$HOME/Library` so we
    // override HOME instead). We do both so the test is cross-platform.
    let data_root = dir.path().join("data");
    fs::create_dir_all(&data_root).unwrap();

    let path = dir.path().join("vault.cloak");
    let pepper = dir.path().join("pepper");
    let mut restore = Command::cargo_bin("cloak").unwrap();
    restore
        .arg("--vault")
        .arg(&path)
        .arg("--no-biometric")
        .env(TEST_MODE_ENV, "1")
        .env("CLOAK_PASSPHRASE", "fresh-pass")
        .env("CLOAK_MNEMONIC", &mnemonic)
        .env("CLOAK_PEPPER_FILE", &pepper)
        .env("CLOAK_DISABLE_ROLLBACK_MIRROR", "1")
        .env("CLOAK_ALLOW_MNEMONIC_STDOUT", "1")
        .env("XDG_DATA_HOME", &data_root)
        .env("HOME", dir.path())
        .env("RUST_LOG", "off")
        .arg("restore")
        .assert()
        .success();

    // Audit lives at one of `<data_dir>/cloak/audit.jsonl`. Walk both
    // candidate locations and look for our entry.
    let candidates = [
        data_root.join("cloak/audit.jsonl"),
        dir.path()
            .join("Library/Application Support/cloak/audit.jsonl"),
    ];
    let body = candidates
        .iter()
        .find_map(|p| fs::read_to_string(p).ok())
        .expect("audit file written somewhere under the test root");
    assert!(
        body.contains("cli.restore"),
        "audit log should record the restore: {body}"
    );
}

#[test]
fn run_requires_explicit_secret_selection() {
    let dir = TempDir::new().unwrap();
    let (mut init, _) = cloak(&dir);
    init.arg("init").assert().success();

    let (mut run, _) = cloak(&dir);
    run.arg("run")
        .arg("--")
        .arg("/usr/bin/env")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "refusing to inject every secret implicitly",
        ));
}
