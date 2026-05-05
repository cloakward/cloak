//! macOS-only integration tests for the audit-token + kqueue peer
//! exit watcher.
//!
//! These tests bind a local Unix-domain socket, spawn a child process
//! that connects to it, and from the daemon side capture the child's
//! `audit_token_t`. We then register a `PeerExitWatcher` on the child
//! PID, kill the child, and assert:
//!
//! 1. The watcher resolves within 100 ms.
//! 2. A `SessionStore` entry bound to that connection has been
//!    revoked.
//! 3. The captured audit-token round-trips through `SessionRecord`
//!    and rejects a one-byte mutation under
//!    `validate_with_identity` (constant-time compare).
//!
//! Linux / Windows skip this file via `cfg`.

#![cfg(target_os = "macos")]

use std::os::fd::AsRawFd;
use std::process::Stdio;
use std::time::Duration as StdDuration;

use chrono::Duration;
use cloak_core::peer_auth::{peer_info_from_unix, PeerExitWatcher, PeerIdentity, PeerIdentityKind};
use cloak_core::session::SessionStore;
use tokio::net::UnixListener;

/// Bind a UDS at a unique tempfile path and spawn a child `cat` that
/// connects to it via `nc -U`. Returns `(listener, child, sock_path)`.
async fn spawn_child_peer() -> (
    tokio::net::UnixStream,
    std::process::Child,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("peer.sock");
    let listener = UnixListener::bind(&path).expect("bind UDS");

    // `nc -U <path>` is the simplest "long-lived peer" available on every
    // macOS host. It connects and then idles waiting for stdin.
    let child = std::process::Command::new("nc")
        .arg("-U")
        .arg(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn nc -U");

    // Accept the child's connection.
    let (stream, _addr) = tokio::time::timeout(StdDuration::from_secs(5), listener.accept())
        .await
        .expect("accept timeout")
        .expect("accept");
    (stream, child, dir)
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_token_captured_at_handshake() {
    let (stream, mut child, _dir) = spawn_child_peer().await;
    let info = peer_info_from_unix(&stream).expect("peer_info_from_unix");

    // The kernel must have given us a 32-byte audit token whose
    // embedded PID matches the child we just spawned.
    let identity = info.identity.expect("identity is present on macOS");
    assert_eq!(identity.kind, PeerIdentityKind::MacAuditToken);
    assert_eq!(identity.bytes.len(), 32);
    assert_eq!(info.pid, child.id() as i32);

    let _ = child.kill();
    let _ = child.wait();
}

#[tokio::test(flavor = "multi_thread")]
async fn kqueue_watcher_fires_and_invalidates_session_within_100ms() {
    let (stream, mut child, _dir) = spawn_child_peer().await;
    let info = peer_info_from_unix(&stream).expect("peer_info");
    let pid = info.pid;
    assert_eq!(pid, child.id() as i32);

    let store = SessionStore::new();
    let conn_id = 42u64;
    let token = store
        .issue(&info, conn_id, Duration::minutes(30))
        .await
        .expect("issue");
    assert!(store.validate(token.as_str(), conn_id).await.is_ok());

    // Register the kqueue watcher BEFORE the kill so we deterministically
    // observe the exit event.
    let watcher = PeerExitWatcher::new(pid).expect("kqueue register");
    assert_eq!(watcher.pid(), pid);

    // Spawn the revocation task: when the watcher fires, drop every
    // session bound to this conn-id. (This mirrors what `daemon::serve_conn`
    // does in production.)
    let revoke_store = store.clone_handle();
    let watch_task = tokio::spawn(async move {
        watcher.wait().await.expect("watcher.wait");
        revoke_store.revoke_by_conn(conn_id).await;
    });

    // Now kill the child and time how long until the session is gone.
    let kill_at = std::time::Instant::now();
    let _ = child.kill();
    let _ = child.wait();

    // Poll for revocation with a 100ms budget.
    let deadline = kill_at + StdDuration::from_millis(100);
    let mut revoked = false;
    while std::time::Instant::now() < deadline {
        if store.validate(token.as_str(), conn_id).await.is_err() {
            revoked = true;
            break;
        }
        tokio::time::sleep(StdDuration::from_millis(2)).await;
    }
    let elapsed = kill_at.elapsed();

    assert!(
        revoked,
        "session was not revoked within 100ms (elapsed: {elapsed:?})"
    );
    assert!(
        elapsed < StdDuration::from_millis(100),
        "revocation took {elapsed:?}, exceeding 100ms budget"
    );

    // Tidy up.
    let _ = tokio::time::timeout(StdDuration::from_millis(50), watch_task).await;

    // Drop the still-open server-side stream last so its peer fd is
    // released cleanly.
    drop(stream);
}

#[tokio::test(flavor = "multi_thread")]
async fn one_byte_mutated_audit_token_rejected_by_validate_with_identity() {
    let (stream, mut child, _dir) = spawn_child_peer().await;
    let info = peer_info_from_unix(&stream).expect("peer_info");

    let store = SessionStore::new();
    let conn_id = 99u64;
    let token = store
        .issue(&info, conn_id, Duration::minutes(30))
        .await
        .expect("issue");

    // Round-trip with the real identity should validate.
    let identity = info.identity.clone().expect("identity present");
    assert!(store
        .validate_with_identity(token.as_str(), conn_id, Some(&identity))
        .await
        .is_ok());

    // Flip a single bit in the embedded pidversion (val[7], bytes
    // 28..32). That's the canonical attacker scenario: same PID,
    // different pidversion → different process.
    let mut bad_bytes = identity.bytes.clone();
    bad_bytes[28] ^= 0x01;
    let bad = PeerIdentity {
        kind: PeerIdentityKind::MacAuditToken,
        bytes: bad_bytes,
    };
    assert!(store
        .validate_with_identity(token.as_str(), conn_id, Some(&bad))
        .await
        .is_err());

    // Drop the FD before reaping the child so we don't leak it.
    let raw = stream.as_raw_fd();
    assert!(raw >= 0);
    drop(stream);

    let _ = child.kill();
    let _ = child.wait();
}
