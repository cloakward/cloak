#![cfg(unix)]

use std::path::Path;
use std::sync::Mutex;

use cloak_core::audit::{AuditDraft, AuditLog, AuditResult, PeerSummary};
use cloak_core::keychain::{
    read_audit_head_anchor, write_audit_head_pending, AuditHead, AuditHeadAnchor,
};
use cloak_core::Error;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn set_anchor_env(pepper: &Path) {
    // SAFETY: these tests hold ENV_LOCK while setting and consuming the vars.
    unsafe {
        std::env::set_var("CLOAK_ENABLE_AUDIT_HEAD", "1");
        std::env::set_var("CLOAK_PEPPER_FILE", pepper);
    }
}

struct AnchorEnvGuard;

impl Drop for AnchorEnvGuard {
    fn drop(&mut self) {
        // SAFETY: these tests hold ENV_LOCK while restoring env state.
        unsafe {
            std::env::remove_var("CLOAK_ENABLE_AUDIT_HEAD");
            std::env::remove_var("CLOAK_PEPPER_FILE");
        }
    }
}

fn anchor_env(pepper: &Path) -> AnchorEnvGuard {
    set_anchor_env(pepper);
    AnchorEnvGuard
}

fn draft(note: &str) -> AuditDraft {
    AuditDraft {
        peer: PeerSummary {
            pid: 1234,
            basename: "audit-anchor-test".to_string(),
            code_sig_hex: None,
        },
        tool: "tool.test".to_string(),
        secret: Some("S1".to_string()),
        target: None,
        result: AuditResult::Ok,
        note: Some(note.to_string()),
    }
}

fn expect_head_mismatch(result: cloak_core::Result<AuditLog>) {
    match result {
        Err(Error::AuditHeadMismatch) => {}
        Err(other) => panic!("expected AuditHeadMismatch, got {other:?}"),
        Ok(_) => panic!("expected AuditHeadMismatch, got Ok"),
    }
}

fn committed_anchor() -> AuditHead {
    match read_audit_head_anchor().expect("read audit anchor") {
        Some(AuditHeadAnchor::Committed(head)) => head,
        other => panic!("expected committed audit anchor, got {other:?}"),
    }
}

#[test]
fn tail_entry_mutation_is_detected_by_anchor() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let pepper = dir.path().join("pepper");
    let _env = anchor_env(&pepper);

    let audit_path = dir.path().join("audit.jsonl");
    let mut log = AuditLog::open(&audit_path).unwrap();
    log.append(draft("first")).unwrap();
    log.append(draft("second")).unwrap();

    let raw = std::fs::read_to_string(&audit_path).unwrap();
    let mut lines: Vec<String> = raw.lines().map(str::to_string).collect();
    let last = lines.last_mut().unwrap();
    *last = last.replace("\"second\"", "\"tampered\"");
    std::fs::write(&audit_path, lines.join("\n") + "\n").unwrap();

    expect_head_mismatch(AuditLog::open(&audit_path));
}

#[test]
fn valid_prefix_truncation_is_detected_by_anchor() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let pepper = dir.path().join("pepper");
    let _env = anchor_env(&pepper);

    let audit_path = dir.path().join("audit.jsonl");
    let mut log = AuditLog::open(&audit_path).unwrap();
    log.append(draft("first")).unwrap();
    log.append(draft("second")).unwrap();
    log.append(draft("third")).unwrap();

    let raw = std::fs::read_to_string(&audit_path).unwrap();
    let lines: Vec<&str> = raw.lines().take(2).collect();
    std::fs::write(&audit_path, lines.join("\n") + "\n").unwrap();

    expect_head_mismatch(AuditLog::open(&audit_path));
}

#[test]
fn missing_anchor_with_nonempty_log_is_fail_closed() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let pepper = dir.path().join("pepper");
    let _env = anchor_env(&pepper);

    let audit_path = dir.path().join("audit.jsonl");
    let mut log = AuditLog::open(&audit_path).unwrap();
    log.append(draft("first")).unwrap();

    std::fs::remove_file(dir.path().join("audit-head")).unwrap();

    expect_head_mismatch(AuditLog::open(&audit_path));
}

#[test]
fn established_profile_full_erasure_fails_closed() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let pepper = dir.path().join("pepper");
    let _env = anchor_env(&pepper);

    let audit_path = dir.path().join("audit.jsonl");
    // Establish a real chain + external anchor.
    let mut log = AuditLog::open(&audit_path).unwrap();
    log.append(draft("first")).unwrap();
    drop(log);

    // Attacker erases BOTH the log file and the external anchor.
    std::fs::remove_file(&audit_path).unwrap();
    std::fs::remove_file(dir.path().join("audit-head")).unwrap();

    // Established-profile open must fail closed (no silent re-genesis).
    match AuditLog::open_for_profile(&audit_path, true) {
        Err(Error::Keychain(msg)) => {
            assert!(msg.contains("adopt-head"), "unexpected message: {msg}")
        }
        Err(other) => panic!("expected fail-closed Keychain error, got {other:?}"),
        Ok(_) => panic!("expected fail-closed Keychain error, got Ok"),
    }

    // The explicit, operator-gated recovery re-establishes the anchor, after
    // which the daemon-style open succeeds again.
    AuditLog::adopt_existing_head(&audit_path).unwrap();
    AuditLog::open_for_profile(&audit_path, true).unwrap();
}

#[test]
fn verify_open_does_not_seed_erased_chain() {
    // The `cloak audit verify` open path must NOT re-seed an erased chain,
    // otherwise an unauthenticated verify would launder a same-UID erasure.
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let pepper = dir.path().join("pepper");
    let _env = anchor_env(&pepper);

    let audit_path = dir.path().join("audit.jsonl");
    let mut log = AuditLog::open(&audit_path).unwrap();
    log.append(draft("first")).unwrap();
    drop(log);

    std::fs::remove_file(&audit_path).unwrap();
    std::fs::remove_file(dir.path().join("audit-head")).unwrap();

    match AuditLog::open_no_seed(&audit_path) {
        Err(Error::Keychain(msg)) => {
            assert!(msg.contains("adopt-head"), "unexpected message: {msg}")
        }
        Err(other) => panic!("expected fail-closed Keychain error, got {other:?}"),
        Ok(_) => panic!("verify open must not seed an erased chain"),
    }
    assert!(
        read_audit_head_anchor().expect("read anchor").is_none(),
        "verify open must not have re-created the anchor"
    );
}

#[test]
fn fresh_profile_still_seeds_silently() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let pepper = dir.path().join("pepper");
    let _env = anchor_env(&pepper);

    let audit_path = dir.path().join("audit.jsonl");
    // A brand-new (un-established) profile seeds genesis with no friction.
    AuditLog::open_for_profile(&audit_path, false).unwrap();
}

#[test]
fn explicit_adopt_existing_head_recovers_legacy_nonempty_log() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let pepper = dir.path().join("pepper");
    let audit_path = dir.path().join("audit.jsonl");

    // Simulate a legacy audit log written before external audit-head anchors
    // existed. With enforcement disabled, appends succeed but no anchor file is
    // created.
    unsafe {
        std::env::remove_var("CLOAK_ENABLE_AUDIT_HEAD");
        std::env::set_var("CLOAK_PEPPER_FILE", &pepper);
    }
    let mut log = AuditLog::open(&audit_path).unwrap();
    log.append(draft("legacy-first")).unwrap();
    drop(log);

    let _env = anchor_env(&pepper);
    expect_head_mismatch(AuditLog::open(&audit_path));

    let adopted = AuditLog::adopt_existing_head(&audit_path).unwrap();
    assert_eq!(adopted.seq, 1);
    assert_eq!(committed_anchor(), adopted);

    let log = AuditLog::open(&audit_path).unwrap();
    assert_eq!(log.verify().unwrap(), 1);
}

#[test]
fn adopt_existing_head_rejects_broken_legacy_chain() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let pepper = dir.path().join("pepper");
    let audit_path = dir.path().join("audit.jsonl");

    unsafe {
        std::env::remove_var("CLOAK_ENABLE_AUDIT_HEAD");
        std::env::set_var("CLOAK_PEPPER_FILE", &pepper);
    }
    let mut log = AuditLog::open(&audit_path).unwrap();
    log.append(draft("legacy-first")).unwrap();
    log.append(draft("legacy-second")).unwrap();
    drop(log);

    let raw = std::fs::read_to_string(&audit_path).unwrap();
    let mut lines: Vec<String> = raw.lines().map(str::to_string).collect();
    let second = lines.get_mut(1).expect("second audit entry exists");
    let mut entry: serde_json::Value = serde_json::from_str(second).unwrap();
    entry["prev_hash"] = serde_json::Value::String("f".repeat(64));
    *second = serde_json::to_string(&entry).unwrap();
    std::fs::write(&audit_path, lines.join("\n") + "\n").unwrap();

    let _env = anchor_env(&pepper);
    match AuditLog::adopt_existing_head(&audit_path) {
        Err(Error::AuditChainBroken(_)) => {}
        Err(other) => panic!("expected AuditChainBroken, got {other:?}"),
        Ok(_) => panic!("expected adopt to reject a broken chain"),
    }
    assert!(
        read_audit_head_anchor()
            .expect("read audit anchor")
            .is_none(),
        "broken legacy chain must not seed an audit anchor"
    );
}

#[test]
fn append_after_truncation_fails_closed() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let pepper = dir.path().join("pepper");
    let _env = anchor_env(&pepper);

    let audit_path = dir.path().join("audit.jsonl");
    let mut log = AuditLog::open(&audit_path).unwrap();
    log.append(draft("first")).unwrap();
    log.append(draft("second")).unwrap();

    let raw = std::fs::read_to_string(&audit_path).unwrap();
    let first = raw.lines().next().unwrap().to_string();
    std::fs::write(&audit_path, first + "\n").unwrap();

    match log.append(draft("after-truncation")) {
        Err(Error::AuditHeadMismatch) => {}
        Err(other) => panic!("expected AuditHeadMismatch, got {other:?}"),
        Ok(_) => panic!("expected append to fail after audit truncation"),
    }
}

#[test]
fn stale_pending_anchor_after_finalization_cannot_downgrade_audit_head() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let pepper = dir.path().join("pepper");
    let _env = anchor_env(&pepper);

    let audit_path = dir.path().join("audit.jsonl");
    let mut log = AuditLog::open(&audit_path).unwrap();
    log.append(draft("first")).unwrap();
    let first_head = committed_anchor();
    log.append(draft("second")).unwrap();
    let second_head = committed_anchor();

    write_audit_head_pending(first_head, second_head).expect("write stale pending marker");

    let raw = std::fs::read_to_string(&audit_path).unwrap();
    let first = raw.lines().next().unwrap().to_string();
    std::fs::write(&audit_path, first + "\n").unwrap();

    expect_head_mismatch(AuditLog::open(&audit_path));
}

#[test]
fn pending_anchor_rejects_old_side_fail_closed() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let pepper = dir.path().join("pepper");
    let _env = anchor_env(&pepper);

    let audit_path = dir.path().join("audit.jsonl");
    let mut log = AuditLog::open(&audit_path).unwrap();
    log.append(draft("first")).unwrap();
    let first_head = committed_anchor();
    log.append(draft("second")).unwrap();
    let second_head = committed_anchor();

    write_audit_head_pending(first_head, second_head).expect("write pending marker");

    let raw = std::fs::read_to_string(&audit_path).unwrap();
    let first = raw.lines().next().unwrap().to_string();
    std::fs::write(&audit_path, first + "\n").unwrap();

    expect_head_mismatch(AuditLog::open(&audit_path));
}
