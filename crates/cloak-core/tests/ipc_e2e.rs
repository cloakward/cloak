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

use cloak_core::biometric;
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

/// Install a deterministic "always deny" biometric stub for every
/// test in this binary, exactly once. Doing this globally (rather than
/// via a per-test RAII guard) avoids a race where two tests running on
/// parallel threads each save/restore the override and one drop's
/// `None` lands in the middle of the other's `vault.show` call. The
/// stub is "deny" so that any `vault.show` without an explicit
/// `skip_biometric: true` opt-out is rejected by the server-side
/// gate — i.e., a same-UID attacker connecting to the daemon socket
/// directly cannot bypass the prompt by lying in the payload.
fn install_deny_authenticator_once() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let stub: biometric::Authenticator = std::sync::Arc::new(|_reason: &str| Ok(false));
        biometric::set_test_authenticator(Some(stub));
    });
}

#[tokio::test]
async fn ipc_e2e_handshake_and_basic_flow() {
    install_deny_authenticator_once();
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

    // 8. vault.show without skip_biometric → daemon fires its own
    //    OS-level prompt. There's no Touch ID hardware / polkit agent
    //    on a CI runner, so `cloak_core::biometric::authenticate`
    //    returns `Ok(false)` and the daemon refuses with
    //    `biometric-failed`. CRITICAL: this is the v1.0 server-side
    //    enforcement — a same-UID attacker who connects to the socket
    //    directly (which is exactly what this test is doing — there
    //    is no `cloak` CLI in the loop) cannot bypass the prompt by
    //    supplying any "user already approved" assertion in the
    //    payload. The daemon ignores client-supplied biometric flags;
    //    only the explicit operator opt-out (`skip_biometric: true`)
    //    is honoured below.
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
        Some("biometric-failed"),
        "vault.show without skip_biometric must hit the daemon-side gate, got {:?}",
        resp.error
    );

    // 8b. v0.9.0-rc3 wire-compat: a client-supplied `biometric_ok: true`
    //     (the old, CLI-trusted field name) must NOT bypass the gate.
    //     This is the regression test for the same-UID attacker case
    //     documented in `docs/THREAT_MODEL.md`.
    let resp = rpc(
        &mut stream,
        Request {
            id: "8b".into(),
            method: "vault.show".into(),
            params: json!({"name": "github_token", "biometric_ok": true}),
            session_token: Some(token.clone()),
        },
    )
    .await;
    assert_eq!(
        resp.error.as_ref().map(|e| e.code.as_str()),
        Some("biometric-failed"),
        "client-supplied biometric_ok must be ignored by the daemon, got {:?}",
        resp.error
    );

    // 9. vault.show with the explicit operator opt-out
    //    (`skip_biometric: true`) bypasses the prompt and returns the
    //    value. This is the documented headless-context escape hatch
    //    forwarded by `cloak --no-biometric show NAME`.
    let resp = rpc(
        &mut stream,
        Request {
            id: "9".into(),
            method: "vault.show".into(),
            params: json!({"name": "github_token", "skip_biometric": true}),
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
    install_deny_authenticator_once();
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
            params: json!({"name": "x", "skip_biometric": true}),
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

/// Regression test for the v1.0 server-side biometric enforcement.
///
/// Threat: a same-UID attacker connects to the `cloakd` UDS directly,
/// bypassing the `cloak` CLI binary. They go through `cli.handshake`
/// (the test binary's basename is in the daemon's `cli_basenames`
/// allowlist, so they pass the peer-identity gate), unlock the vault
/// over IPC, and then try to call `vault.show` while supplying any
/// "user already approved" assertion they can think of. Before v1.0
/// the daemon trusted a CLI-side `biometric_ok: true` flag and would
/// have returned the plaintext. v1.0 fires the OS-level prompt
/// **server-side** in `cloakd` itself and ignores any client-supplied
/// biometric assertion: the only escape hatch is the explicit
/// `skip_biometric: true` opt-out for documented headless contexts.
///
/// We install an "always deny" biometric stub so the test asserts the
/// server-side gate without popping a real Touch ID dialog. With the
/// stub installed, any `vault.show` that is NOT explicitly opted-out
/// must fail with `biometric-failed`.
#[tokio::test]
async fn ipc_e2e_same_uid_attacker_cannot_bypass_biometric() {
    install_deny_authenticator_once();
    let (_pol, basename) = open_policy();
    let Some((socket_path, _dir, shutdown, handle)) = spawn_daemon(basename.clone()).await else {
        return;
    };

    let mut stream = UnixStream::connect(&socket_path).await.expect("connect");

    // Handshake as the CLI peer (passes basename allowlist).
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
    assert!(resp.error.is_none(), "handshake: {:?}", resp.error);
    let token = resp.result.unwrap()["session_token"]
        .as_str()
        .expect("token")
        .to_string();

    // Initialize + unlock + add — interactive (keychain) on macOS, may
    // be skipped if the keychain isn't available on this runner.
    let resp = rpc(
        &mut stream,
        Request {
            id: "2".into(),
            method: "vault.initialize".into(),
            params: json!({"passphrase": "test-passphrase-for-attacker-test"}),
            session_token: Some(token.clone()),
        },
    )
    .await;
    if let Some(e) = resp.error.as_ref() {
        if e.code == "internal-error" && e.message.contains("keychain") {
            eprintln!("attacker test: skipping (keychain unavailable)");
            shutdown.notify_waiters();
            handle.abort();
            return;
        }
        panic!("vault.initialize failed: {e:?}");
    }
    let resp = rpc(
        &mut stream,
        Request {
            id: "3".into(),
            method: "vault.add".into(),
            params: json!({
                "name": "the_secret",
                "kind": "api_key",
                "tags": [],
                "value": "must-not-leak"
            }),
            session_token: Some(token.clone()),
        },
    )
    .await;
    assert!(resp.error.is_none(), "add: {:?}", resp.error);

    // ---- Attacker round 1: vanilla `vault.show`. The daemon's
    //      server-side biometric gate fires (via our deny stub) and
    //      returns `biometric-failed`. No plaintext leaks.
    let resp = rpc(
        &mut stream,
        Request {
            id: "4".into(),
            method: "vault.show".into(),
            params: json!({"name": "the_secret"}),
            session_token: Some(token.clone()),
        },
    )
    .await;
    assert!(
        resp.result.is_none(),
        "attacker must not get a plaintext value, got {:?}",
        resp.result
    );
    assert_eq!(
        resp.error.as_ref().map(|e| e.code.as_str()),
        Some("biometric-failed"),
        "attacker: {:?}",
        resp.error
    );

    // ---- Attacker round 2: try every "I already approved" wording
    //      we can think of. None of them are honoured by the daemon —
    //      the daemon ignores client-supplied biometric assertions.
    for bypass in [
        json!({"name": "the_secret", "biometric_ok": true}),
        json!({"name": "the_secret", "biometric": true}),
        json!({"name": "the_secret", "user_present": true}),
        json!({"name": "the_secret", "approved": true}),
    ] {
        let resp = rpc(
            &mut stream,
            Request {
                id: "5".into(),
                method: "vault.show".into(),
                params: bypass.clone(),
                session_token: Some(token.clone()),
            },
        )
        .await;
        assert!(
            resp.result.is_none(),
            "attacker bypassed with {bypass:?}, got {:?}",
            resp.result
        );
        assert_eq!(
            resp.error.as_ref().map(|e| e.code.as_str()),
            Some("biometric-failed"),
            "attacker bypass with {bypass:?}: {:?}",
            resp.error
        );
    }

    // ---- Sanity: the explicit operator opt-out (`skip_biometric`)
    //      DOES bypass the prompt — that's the documented headless
    //      escape hatch forwarded by `cloak --no-biometric show`.
    let resp = rpc(
        &mut stream,
        Request {
            id: "6".into(),
            method: "vault.show".into(),
            params: json!({"name": "the_secret", "skip_biometric": true}),
            session_token: Some(token.clone()),
        },
    )
    .await;
    assert!(
        resp.error.is_none(),
        "skip_biometric path: {:?}",
        resp.error
    );
    assert_eq!(resp.result.unwrap()["value"], json!("must-not-leak"));

    drop(stream);
    shutdown.notify_waiters();
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}
