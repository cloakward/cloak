//! End-to-end IPC test: spawn the daemon on a tmp socket, run the
//! handshake, and exercise `vault.is_initialized` / `vault.initialize`
//! / `vault.add` / `vault.list`.
//!
//! This test touches the real OS keychain (for the pepper) on macOS.
//! On platforms where the keychain is unavailable, the
//! `vault.initialize` step is skipped — the handshake + framing is
//! still asserted.
//!
//! On environments where binding a UDS at all is impossible (e.g. some
//! sandboxed CI machines), the test exits early with a printed reason.

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use cloak_core::daemon::{self};
use cloak_core::ipc::{read_response_json, write_request_json, Request, Response};
use cloak_core::peer_auth::PeerPolicy;
use serde_json::json;
use tempfile::TempDir;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;

/// Build an open peer policy keyed off the running test binary so the
/// daemon's peer-auth gate accepts our connections.
fn open_policy() -> (PeerPolicy, String) {
    let exe = std::env::current_exe().expect("current_exe");
    let basename = exe
        .file_name()
        .expect("file_name")
        .to_string_lossy()
        .into_owned();
    (
        PeerPolicy {
            allowed_basenames: vec![basename.clone()],
            require_same_uid: true,
        },
        basename,
    )
}

/// Spawn the daemon on a tmp socket. Returns (socket_path, vault_dir,
/// shutdown_notify, join_handle).
async fn spawn_daemon(
    cli_basename: String,
) -> Option<(PathBuf, TempDir, Arc<Notify>, tokio::task::JoinHandle<()>)> {
    // Disable the rollback-counter mirror for the same reason as in
    // `handlers_e2e.rs`: a fresh per-test vault would otherwise be
    // rejected by a stale keychain mirror left by a prior run.
    // SAFETY: required by std 1.84+ for env mutation.
    unsafe {
        std::env::set_var("CLOAK_DISABLE_ROLLBACK_MIRROR", "1");
    }

    let dir = TempDir::new().expect("tempdir");
    let socket_path = dir.path().join("cloakd.sock");
    let vault_path = dir.path().join("vault.cloak");
    let policy_path = dir.path().join("policy.toml");
    let audit_path = dir.path().join("audit.jsonl");

    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ipc_e2e: skipping — cannot bind UDS: {e}");
            return None;
        }
    };

    let (policy, _bn) = open_policy();
    let shutdown = Arc::new(Notify::new());
    let shutdown2 = shutdown.clone();
    let socket_path2 = socket_path.clone();

    let handle = tokio::spawn(async move {
        let _ = daemon::run_with(
            listener,
            vault_path,
            socket_path2,
            policy,
            vec![cli_basename],
            shutdown2,
            policy_path,
            audit_path,
        )
        .await;
    });

    // Tiny delay so the listener is ready (bind is sync, but spawn is async).
    tokio::time::sleep(Duration::from_millis(20)).await;
    Some((socket_path, dir, shutdown, handle))
}

async fn rpc(stream: &mut UnixStream, req: Request) -> Response {
    write_request_json(stream, &req).await.expect("write");
    read_response_json(stream).await.expect("read")
}

#[tokio::test]
async fn ipc_e2e_handshake_and_basic_flow() {
    let (_pol, basename) = open_policy();
    let Some((socket_path, _dir, shutdown, handle)) = spawn_daemon(basename.clone()).await else {
        return;
    };

    let mut stream = UnixStream::connect(&socket_path).await.expect("connect");

    // 1. Handshake.
    let resp = rpc(
        &mut stream,
        Request {
            id: "1".into(),
            method: "cli.handshake".into(),
            params: json!({}),
            session_token: None,
        },
    )
    .await;
    assert!(resp.error.is_none(), "handshake error: {:?}", resp.error);
    let token = resp.result.unwrap()["session_token"]
        .as_str()
        .expect("token")
        .to_string();
    assert!(!token.is_empty());

    // 2. vault.is_initialized → false.
    let resp = rpc(
        &mut stream,
        Request {
            id: "2".into(),
            method: "vault.is_initialized".into(),
            params: json!({}),
            session_token: Some(token.clone()),
        },
    )
    .await;
    assert_eq!(resp.error, None);
    assert_eq!(resp.result.unwrap()["initialized"], json!(false));

    // 3. unknown method → unknown-method.
    let resp = rpc(
        &mut stream,
        Request {
            id: "3".into(),
            method: "vault.does_not_exist".into(),
            params: json!({}),
            session_token: Some(token.clone()),
        },
    )
    .await;
    assert_eq!(
        resp.error.as_ref().map(|e| e.code.as_str()),
        Some("unknown-method")
    );

    // 4. vault.list while locked → vault-locked.
    let resp = rpc(
        &mut stream,
        Request {
            id: "4".into(),
            method: "vault.list".into(),
            params: json!({}),
            session_token: Some(token.clone()),
        },
    )
    .await;
    assert_eq!(
        resp.error.as_ref().map(|e| e.code.as_str()),
        Some("vault-locked")
    );

    // 5. Try vault.initialize. This touches the real keychain on macOS;
    //    skip the rest if it's not available.
    let resp = rpc(
        &mut stream,
        Request {
            id: "5".into(),
            method: "vault.initialize".into(),
            params: json!({"passphrase": "test-passphrase-for-e2e"}),
            session_token: Some(token.clone()),
        },
    )
    .await;
    if let Some(e) = resp.error.as_ref() {
        if e.code == "internal-error" && e.message.contains("keychain") {
            eprintln!("ipc_e2e: skipping initialize-dependent steps (keychain unavailable)");
            shutdown.notify_waiters();
            handle.abort();
            return;
        }
        panic!("vault.initialize failed: {e:?}");
    }

    // 6. vault.add.
    let resp = rpc(
        &mut stream,
        Request {
            id: "6".into(),
            method: "vault.add".into(),
            params: json!({
                "name": "github_token",
                "kind": "api_key",
                "tags": ["prod"],
                "value": "ghp_redacted_test"
            }),
            session_token: Some(token.clone()),
        },
    )
    .await;
    assert!(resp.error.is_none(), "add: {:?}", resp.error);
    assert_eq!(resp.result.unwrap()["version"], json!(1));

    // 7. vault.list.
    let resp = rpc(
        &mut stream,
        Request {
            id: "7".into(),
            method: "vault.list".into(),
            params: json!({}),
            session_token: Some(token.clone()),
        },
    )
    .await;
    assert!(resp.error.is_none(), "list: {:?}", resp.error);
    let secrets = resp.result.unwrap()["secrets"].clone();
    assert_eq!(secrets.as_array().unwrap().len(), 1);
    assert_eq!(secrets[0]["name"], json!("github_token"));
    assert_eq!(secrets[0]["kind"], json!("api_key"));

    // 8. vault.show without biometric_ok → policy-denied.
    let resp = rpc(
        &mut stream,
        Request {
            id: "8".into(),
            method: "vault.show".into(),
            params: json!({"name": "github_token"}),
            session_token: Some(token.clone()),
        },
    )
    .await;
    assert_eq!(
        resp.error.as_ref().map(|e| e.code.as_str()),
        Some("policy-denied")
    );

    // 9. vault.show with biometric_ok=true returns the value.
    let resp = rpc(
        &mut stream,
        Request {
            id: "9".into(),
            method: "vault.show".into(),
            params: json!({"name": "github_token", "biometric_ok": true}),
            session_token: Some(token.clone()),
        },
    )
    .await;
    assert!(resp.error.is_none(), "show: {:?}", resp.error);
    assert_eq!(resp.result.unwrap()["value"], json!("ghp_redacted_test"));

    // 10. Bogus token → session-expired.
    let resp = rpc(
        &mut stream,
        Request {
            id: "10".into(),
            method: "vault.list".into(),
            params: json!({}),
            session_token: Some("not-a-real-token".into()),
        },
    )
    .await;
    assert_eq!(
        resp.error.as_ref().map(|e| e.code.as_str()),
        Some("session-expired")
    );

    // Cleanup.
    drop(stream);
    shutdown.notify_waiters();
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn ipc_e2e_mcp_peer_cannot_call_cli_only_methods() {
    // Spawn the daemon with `cli_basenames` set to *something other than*
    // our test binary — so the test peer is treated as MCP.
    let Some((socket_path, _dir, shutdown, handle)) = spawn_daemon("cloak".to_string()).await
    else {
        return;
    };

    let mut stream = UnixStream::connect(&socket_path).await.expect("connect");

    let resp = rpc(
        &mut stream,
        Request {
            id: "1".into(),
            method: "mcp.handshake".into(),
            params: json!({}),
            session_token: None,
        },
    )
    .await;
    assert!(resp.error.is_none());
    let token = resp.result.unwrap()["session_token"]
        .as_str()
        .unwrap()
        .to_string();

    // CLI-only method invoked by an MCP peer → peer-not-trusted.
    let resp = rpc(
        &mut stream,
        Request {
            id: "2".into(),
            method: "vault.show".into(),
            params: json!({"name": "x", "biometric_ok": true}),
            session_token: Some(token.clone()),
        },
    )
    .await;
    assert_eq!(
        resp.error.as_ref().map(|e| e.code.as_str()),
        Some("peer-not-trusted")
    );

    // Read-only is fine (vault.is_initialized doesn't need unlock).
    let resp = rpc(
        &mut stream,
        Request {
            id: "3".into(),
            method: "vault.is_initialized".into(),
            params: json!({}),
            session_token: Some(token),
        },
    )
    .await;
    assert!(resp.error.is_none());
    assert_eq!(resp.result.unwrap()["initialized"], json!(false));

    drop(stream);
    shutdown.notify_waiters();
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}
