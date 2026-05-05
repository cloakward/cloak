//! End-to-end tests for the privileged tool handlers.
//!
//! Spins up the daemon against a temp socket, temp vault, temp policy
//! file, and temp audit log. Then exercises:
//! - `tool.sign_request` with `hmac-sha256` (asserts the signature is the
//!   exact HMAC over the documented canonical string).
//! - A negative case where the secret is *not* in the policy → `policy-denied`.
//! - `tool.proxy_http` against a host that's not in `allowed_hosts` → `policy-denied`.
//! - `tool.proxy_http` against a tiny in-process mock server → `200` echoed.
//! - `tool.query_audit` returns the entries written above.
//! - `audit.verify()` confirms the chain length matches what we expect.
//!
//! These tests touch the real macOS keychain (for the vault pepper) when
//! the daemon initializes the vault. If the keychain is unavailable, we
//! skip the test — same convention as `ipc_e2e.rs`.

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use cloak_core::audit::AuditLog;
use cloak_core::daemon;
use cloak_core::ipc::{read_response_json, write_request_json, Request, Response};
use cloak_core::peer_auth::PeerPolicy;
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::sync::Notify;

/// Cross-test async mutex: tests that install a process-global STS test
/// factory (`set_test_sts_factory`) must serialize so they don't clobber
/// each other's mock when cargo runs them in parallel. Uses a tokio
/// `Mutex` since the guard is held across `.await` points.
async fn aws_sts_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: once_cell::sync::Lazy<tokio::sync::Mutex<()>> =
        once_cell::sync::Lazy::new(|| tokio::sync::Mutex::new(()));
    LOCK.lock().await
}

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

/// Spawn the daemon. Returns (socket_path, tempdir, audit_path,
/// shutdown_notify, join_handle, basename).
async fn spawn_daemon(
    cli_basename: String,
    policy_toml: &str,
) -> Option<(
    PathBuf,
    TempDir,
    PathBuf,
    Arc<Notify>,
    tokio::task::JoinHandle<()>,
)> {
    let dir = TempDir::new().expect("tempdir");
    let socket_path = dir.path().join("cloakd.sock");
    let vault_path = dir.path().join("vault.cloak");
    let policy_path = dir.path().join("policy.toml");
    let audit_path = dir.path().join("audit.jsonl");
    std::fs::write(&policy_path, policy_toml).expect("write policy");

    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("handlers_e2e: skipping — cannot bind UDS: {e}");
            return None;
        }
    };

    let (policy, _bn) = open_policy();
    let shutdown = Arc::new(Notify::new());
    let shutdown2 = shutdown.clone();
    let socket_path2 = socket_path.clone();
    let policy_path2 = policy_path.clone();
    let audit_path2 = audit_path.clone();

    let handle = tokio::spawn(async move {
        let _ = daemon::run_with(
            listener,
            vault_path,
            socket_path2,
            policy,
            vec![cli_basename],
            shutdown2,
            policy_path2,
            audit_path2,
        )
        .await;
    });

    tokio::time::sleep(Duration::from_millis(20)).await;
    Some((socket_path, dir, audit_path, shutdown, handle))
}

async fn rpc(stream: &mut UnixStream, req: Request) -> Response {
    write_request_json(stream, &req).await.expect("write");
    read_response_json(stream).await.expect("read")
}

/// Open a connection, do a CLI handshake, init+unlock the vault, and add
/// a few test secrets. Returns (stream, session_token). On keychain
/// failure (vault.initialize fails with a keychain error), returns None
/// so the test can early-exit.
async fn connect_init_unlock_seed(
    socket_path: &PathBuf,
    secrets: &[(&str, &str)],
) -> Option<(UnixStream, String)> {
    let mut stream = UnixStream::connect(socket_path).await.expect("connect");

    let resp = rpc(
        &mut stream,
        Request {
            id: "h".into(),
            method: "cli.handshake".into(),
            params: json!({}),
            session_token: None,
        },
    )
    .await;
    assert!(resp.error.is_none(), "handshake error: {:?}", resp.error);
    let token = resp.result.unwrap()["session_token"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = rpc(
        &mut stream,
        Request {
            id: "init".into(),
            method: "vault.initialize".into(),
            params: json!({"passphrase": "test-passphrase-handlers"}),
            session_token: Some(token.clone()),
        },
    )
    .await;
    if let Some(e) = resp.error.as_ref() {
        if e.code == "internal-error" && e.message.contains("keychain") {
            eprintln!("handlers_e2e: skipping (keychain unavailable)");
            return None;
        }
        panic!("vault.initialize failed: {e:?}");
    }

    for (i, (name, value)) in secrets.iter().enumerate() {
        let resp = rpc(
            &mut stream,
            Request {
                id: format!("add{i}"),
                method: "vault.add".into(),
                params: json!({
                    "name": name,
                    "kind": "api_key",
                    "tags": [],
                    "value": value,
                }),
                session_token: Some(token.clone()),
            },
        )
        .await;
        assert!(resp.error.is_none(), "add({name}): {:?}", resp.error);
    }

    Some((stream, token))
}

#[tokio::test]
async fn sign_request_hmac_sha256_happy_path() {
    let policy = r#"
        [default]
        action = "deny"
        [[secrets]]
        name = "TEST_HMAC_KEY"
        [secrets.tools.sign_request]
        allow = true
    "#;

    let (_pol, basename) = open_policy();
    let Some((socket, _dir, audit_path, shutdown, handle)) = spawn_daemon(basename, policy).await
    else {
        return;
    };

    let Some((mut stream, token)) =
        connect_init_unlock_seed(&socket, &[("TEST_HMAC_KEY", "sekret")]).await
    else {
        shutdown.notify_waiters();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        return;
    };

    // Call sign_request.
    let resp = rpc(
        &mut stream,
        Request {
            id: "s1".into(),
            method: "tool.sign_request".into(),
            params: json!({
                "secret_name": "TEST_HMAC_KEY",
                "scheme": "hmac-sha256",
                "method": "GET",
                "url": "https://example.com/foo",
            }),
            session_token: Some(token.clone()),
        },
    )
    .await;
    assert!(resp.error.is_none(), "sign_request: {:?}", resp.error);
    let result = resp.result.unwrap();
    let sig = result["headers"]["X-Cloak-Signature"]
        .as_str()
        .expect("sig header");

    // Recompute and assert exact match.
    let body_sha = hex::encode(Sha256::digest(b""));
    let canonical = format!("GET\n{}\n{}\n", "https://example.com/foo", body_sha);
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(b"sekret").unwrap();
    mac.update(canonical.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    assert_eq!(sig, expected);

    // Negative: a *different* secret name not in the policy → policy-denied.
    let resp = rpc(
        &mut stream,
        Request {
            id: "s2".into(),
            method: "vault.add".into(),
            params: json!({
                "name": "OTHER_KEY",
                "kind": "api_key",
                "tags": [],
                "value": "v",
            }),
            session_token: Some(token.clone()),
        },
    )
    .await;
    assert!(resp.error.is_none());

    let resp = rpc(
        &mut stream,
        Request {
            id: "s3".into(),
            method: "tool.sign_request".into(),
            params: json!({
                "secret_name": "OTHER_KEY",
                "scheme": "hmac-sha256",
                "method": "GET",
                "url": "https://example.com/foo",
            }),
            session_token: Some(token.clone()),
        },
    )
    .await;
    assert_eq!(
        resp.error.as_ref().map(|e| e.code.as_str()),
        Some("policy-denied")
    );

    // The signature must NOT contain the secret material — assert sig is
    // the right length and only hex.
    assert_eq!(sig.len(), 64);
    assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(!sig.contains("sekret"));

    // tool.query_audit returns entries we wrote.
    let resp = rpc(
        &mut stream,
        Request {
            id: "q1".into(),
            method: "tool.query_audit".into(),
            params: json!({}),
            session_token: Some(token.clone()),
        },
    )
    .await;
    // query_audit isn't allowed in our minimal policy by default. Add an
    // override and re-query — but our policy here is deny by default with
    // a sign_request rule, so query_audit will be denied. Verify.
    assert_eq!(
        resp.error.as_ref().map(|e| e.code.as_str()),
        Some("policy-denied"),
        "query_audit should be policy-denied without a tools.query_audit rule"
    );

    // audit_log.verify() — the chain length should be > 0. Open the file
    // out-of-band (separate AuditLog handle).
    let audit = AuditLog::open(&audit_path).unwrap();
    let count = audit.verify().expect("audit verifies");
    assert!(count >= 3, "expected >=3 audit entries, got {count}");

    drop(stream);
    shutdown.notify_waiters();
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn sign_request_does_not_leak_secret_into_response() {
    let policy = r#"
        [default]
        action = "deny"
        [[secrets]]
        name = "LEAK_TEST_KEY"
        [secrets.tools.sign_request]
        allow = true
    "#;

    let (_pol, basename) = open_policy();
    let Some((socket, _dir, _audit, shutdown, handle)) = spawn_daemon(basename, policy).await
    else {
        return;
    };

    let secret_value = "super-secret-marker-12345";
    let Some((mut stream, token)) =
        connect_init_unlock_seed(&socket, &[("LEAK_TEST_KEY", secret_value)]).await
    else {
        shutdown.notify_waiters();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        return;
    };

    let resp = rpc(
        &mut stream,
        Request {
            id: "s1".into(),
            method: "tool.sign_request".into(),
            params: json!({
                "secret_name": "LEAK_TEST_KEY",
                "scheme": "hmac-sha256",
                "method": "POST",
                "url": "https://example.com/x",
                "body_b64": base64::engine::general_purpose::STANDARD.encode(b"some body"),
            }),
            session_token: Some(token.clone()),
        },
    )
    .await;
    assert!(resp.error.is_none());
    let serialized = serde_json::to_string(&resp.result.unwrap()).unwrap();
    assert!(
        !serialized.contains(secret_value),
        "response leaked secret material: {serialized}"
    );

    drop(stream);
    shutdown.notify_waiters();
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn proxy_http_disallowed_host_denied() {
    let policy = r#"
        [default]
        action = "deny"
        [[secrets]]
        name = "API_KEY"
        [secrets.tools.proxy_authenticated_http_request]
        allowed_hosts = ["allowed.example.com"]
    "#;

    let (_pol, basename) = open_policy();
    let Some((socket, _dir, _audit, shutdown, handle)) = spawn_daemon(basename, policy).await
    else {
        return;
    };

    let Some((mut stream, token)) =
        connect_init_unlock_seed(&socket, &[("API_KEY", "tok-redacted")]).await
    else {
        shutdown.notify_waiters();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        return;
    };

    let resp = rpc(
        &mut stream,
        Request {
            id: "p1".into(),
            method: "tool.proxy_http".into(),
            params: json!({
                "secret_name": "API_KEY",
                "method": "GET",
                "url": "https://disallowed.example.com/x",
                "auth_scheme": "bearer",
            }),
            session_token: Some(token),
        },
    )
    .await;
    assert_eq!(
        resp.error.as_ref().map(|e| e.code.as_str()),
        Some("policy-denied")
    );

    drop(stream);
    shutdown.notify_waiters();
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}

/// Run a 1-shot HTTP server on a random local port. Returns
/// (port, JoinHandle<Vec<u8>>) — the join handle yields the raw request
/// bytes the server received, so the test can assert what the daemon
/// sent.
async fn one_shot_http_server() -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        let (mut sock, _addr) = listener.accept().await.expect("accept");
        let mut buf = vec![0u8; 8192];
        // Read until we see CRLFCRLF (end of headers). Body of the test
        // request is empty so this is enough.
        let mut total = 0;
        loop {
            let n = sock.read(&mut buf[total..]).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            total += n;
            if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            if total >= buf.len() {
                break;
            }
        }
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Type: text/plain\r\n\r\npong";
        let _ = sock.write_all(resp).await;
        let _ = sock.shutdown().await;
        buf[..total].to_vec()
    });
    (port, handle)
}

#[tokio::test]
async fn proxy_http_allowed_host_round_trip() {
    // Stand up an in-process HTTP server first so we know the port.
    let (port, server_handle) = one_shot_http_server().await;

    let policy = r#"
        [default]
        action = "deny"
        [[secrets]]
        name = "API_KEY"
        [secrets.tools.proxy_authenticated_http_request]
        allowed_hosts = ["127.0.0.1"]
    "#;
    let _ = port; // referenced via URL below

    let (_pol, basename) = open_policy();
    let Some((socket, _dir, _audit, shutdown, handle)) = spawn_daemon(basename, policy).await
    else {
        server_handle.abort();
        return;
    };

    let Some((mut stream, token)) =
        connect_init_unlock_seed(&socket, &[("API_KEY", "secret-bearer-tok")]).await
    else {
        server_handle.abort();
        shutdown.notify_waiters();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        return;
    };

    let url = format!("http://127.0.0.1:{port}/ping");
    let resp = rpc(
        &mut stream,
        Request {
            id: "p1".into(),
            method: "tool.proxy_http".into(),
            params: json!({
                "secret_name": "API_KEY",
                "method": "GET",
                "url": url,
                "auth_scheme": "bearer",
                "headers": {"User-Agent": "cloak-test"},
            }),
            session_token: Some(token),
        },
    )
    .await;
    assert!(resp.error.is_none(), "proxy_http: {:?}", resp.error);
    let r = resp.result.unwrap();
    assert_eq!(r["status"].as_u64().unwrap(), 200);
    let body_b64 = r["body_b64"].as_str().unwrap();
    let body = base64::engine::general_purpose::STANDARD
        .decode(body_b64)
        .unwrap();
    assert_eq!(body, b"pong");

    // Verify the response did NOT echo the bearer token anywhere.
    let serialized = serde_json::to_string(&r).unwrap();
    assert!(!serialized.contains("secret-bearer-tok"));

    // The captured request bytes should contain "Authorization: Bearer
    // secret-bearer-tok" — proves the daemon attached it on the wire,
    // even though it never came back to the caller.
    let request_bytes = tokio::time::timeout(Duration::from_secs(2), server_handle)
        .await
        .expect("server task")
        .expect("server bytes");
    let request_text = String::from_utf8_lossy(&request_bytes);
    let request_lc = request_text.to_ascii_lowercase();
    assert!(
        request_lc.contains("authorization: bearer secret-bearer-tok"),
        "expected auth header on the wire, got: {request_text}"
    );

    drop(stream);
    shutdown.notify_waiters();
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn query_audit_returns_entries_when_allowed() {
    let policy = r#"
        [default]
        action = "deny"
        [tools.query_audit]
        allow = true
        [[secrets]]
        name = "TEST_HMAC_KEY"
        [secrets.tools.sign_request]
        allow = true
    "#;

    let (_pol, basename) = open_policy();
    let Some((socket, _dir, audit_path, shutdown, handle)) = spawn_daemon(basename, policy).await
    else {
        return;
    };

    let Some((mut stream, token)) =
        connect_init_unlock_seed(&socket, &[("TEST_HMAC_KEY", "sekret")]).await
    else {
        shutdown.notify_waiters();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        return;
    };

    // Make a few sign_request calls so we have entries to query.
    for i in 0..3 {
        let resp = rpc(
            &mut stream,
            Request {
                id: format!("s{i}"),
                method: "tool.sign_request".into(),
                params: json!({
                    "secret_name": "TEST_HMAC_KEY",
                    "scheme": "hmac-sha256",
                    "method": "GET",
                    "url": "https://example.com/foo",
                }),
                session_token: Some(token.clone()),
            },
        )
        .await;
        assert!(resp.error.is_none());
    }

    // Query for `tool.sign_request` entries.
    let resp = rpc(
        &mut stream,
        Request {
            id: "q1".into(),
            method: "tool.query_audit".into(),
            params: json!({"tool": "tool.sign_request"}),
            session_token: Some(token.clone()),
        },
    )
    .await;
    assert!(resp.error.is_none(), "query_audit: {:?}", resp.error);
    let entries = resp.result.unwrap()["entries"].as_array().unwrap().clone();
    assert_eq!(entries.len(), 3);
    for e in &entries {
        assert_eq!(e["tool"].as_str(), Some("tool.sign_request"));
        assert_eq!(e["result"].as_str(), Some("ok"));
        // Ensure no plaintext secret body bytes leak in.
        let s = serde_json::to_string(e).unwrap();
        assert!(!s.contains("sekret"));
    }

    // The full audit chain should still verify.
    let audit = AuditLog::open(&audit_path).unwrap();
    let total = audit.verify().expect("verifies");
    assert!(total >= 4, "expected at least 4 entries, got {total}");

    drop(stream);
    shutdown.notify_waiters();
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}

/// Drive `tool.mint_token` (kind=aws-sts) through the full daemon path with
/// a mocked STS client. The mocked client returns a known credential set;
/// we assert the daemon's response shape matches IPC_WIRE.md and the token
/// envelope decodes back to those credentials. No network I/O.
#[tokio::test]
async fn mint_token_aws_sts_real_path_with_mock() {
    use aws_sdk_sts::operation::get_session_token::GetSessionTokenOutput;
    use aws_sdk_sts::types::Credentials as StsCredentials;
    use aws_smithy_mocks::{mock, mock_client, RuleMode};
    use aws_smithy_types::DateTime as SmithyDateTime;
    use cloak_core::handlers::set_test_sts_factory;

    let _aws_lock = aws_sts_test_lock().await;

    let policy = r#"
        [default]
        action = "deny"
        [[secrets]]
        name = "AWS_ROOT"
        [secrets.tools.mint_short_lived_token]
        allow = true
    "#;

    // Pin the mock STS expiration to 600s in the future so we can compare
    // it against the daemon's `expires_at` to-the-second.
    let expiration_unix: i64 = (chrono::Utc::now() + chrono::Duration::seconds(600)).timestamp();

    // Install a thread-safe factory that hands out a fresh mocked client
    // per call (the daemon may call this from a different task).
    let factory: cloak_core::handlers::StsClientFactory = std::sync::Arc::new(
        move |_akid: &str, _secret: &str, _region: &str| -> aws_sdk_sts::Client {
            let creds = StsCredentials::builder()
                .access_key_id("ASIAMOCKEDEXAMPLE")
                .secret_access_key("mockedsecret/abcdEXAMPLE")
                .session_token("FwoGmocksessiontoken==")
                .expiration(SmithyDateTime::from_secs(expiration_unix))
                .build()
                .expect("StsCredentials build");
            let rule = mock!(aws_sdk_sts::Client::get_session_token)
                .match_requests(|req| req.duration_seconds() == Some(900))
                .then_output(move || {
                    GetSessionTokenOutput::builder()
                        .credentials(creds.clone())
                        .build()
                });
            mock_client!(aws_sdk_sts, RuleMode::Sequential, &[&rule])
        },
    );
    let _prev = set_test_sts_factory(Some(factory));

    let (_pol, basename) = open_policy();
    let Some((socket, _dir, audit_path, shutdown, handle)) = spawn_daemon(basename, policy).await
    else {
        set_test_sts_factory(None);
        return;
    };

    let Some((mut stream, token)) =
        connect_init_unlock_seed(&socket, &[("AWS_ROOT", "AKIAEXAMPLE:secretexample")]).await
    else {
        set_test_sts_factory(None);
        shutdown.notify_waiters();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        return;
    };

    let resp = rpc(
        &mut stream,
        Request {
            id: "m1".into(),
            method: "tool.mint_token".into(),
            params: json!({
                "secret_name": "AWS_ROOT",
                "kind": "aws-sts",
                "ttl_seconds": 900,
                "scope": {"region": "us-east-1"},
            }),
            session_token: Some(token),
        },
    )
    .await;
    assert!(resp.error.is_none(), "mint_token: {:?}", resp.error);
    let r = resp.result.unwrap();
    let tok = r["token"].as_str().unwrap();
    let expires_at = r["expires_at"].as_str().expect("expires_at");

    // Token must be base64 of a JSON object with the four expected fields.
    let raw = base64::engine::general_purpose::STANDARD
        .decode(tok)
        .expect("token is valid base64");
    let env: serde_json::Value =
        serde_json::from_slice(&raw).expect("token decodes to JSON object");
    let env_obj = env.as_object().expect("token is JSON object");
    assert!(env_obj.contains_key("access_key_id"));
    assert!(env_obj.contains_key("secret_access_key"));
    assert!(env_obj.contains_key("session_token"));
    assert!(env_obj.contains_key("expiration"));
    assert_eq!(env_obj["access_key_id"].as_str(), Some("ASIAMOCKEDEXAMPLE"));
    assert_eq!(
        env_obj["session_token"].as_str(),
        Some("FwoGmocksessiontoken==")
    );

    // expires_at matches the mock's expiration to the second.
    let parsed = chrono::DateTime::parse_from_rfc3339(expires_at)
        .expect("rfc3339")
        .with_timezone(&chrono::Utc);
    assert_eq!(parsed.timestamp(), expiration_unix);

    // No leakage of the input parent secret in the response.
    let serialized = serde_json::to_string(&r).unwrap();
    assert!(!serialized.contains("AKIAEXAMPLE"));
    assert!(!serialized.contains("secretexample"));

    let audit = AuditLog::open(&audit_path).unwrap();
    let total = audit.verify().expect("verifies");
    assert!(total >= 1);

    // The audit chain note also must not contain the input AKID/secret.
    let raw_audit = std::fs::read_to_string(&audit_path).unwrap_or_default();
    assert!(
        !raw_audit.contains("AKIAEXAMPLE"),
        "audit contains AKID: {raw_audit}"
    );
    assert!(
        !raw_audit.contains("secretexample"),
        "audit contains secret: {raw_audit}"
    );

    drop(stream);
    shutdown.notify_waiters();
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    set_test_sts_factory(None);
}

/// Property-style: every privileged tool that touches a secret must NOT
/// emit any byte of the input secret either in its IPC response or in
/// the appended audit entry. This guards the W1 handlers (sign_request
/// scheme=aws-sigv4 and mint_token kind=aws-sts) against future leakage
/// regressions.
#[tokio::test]
async fn no_leak_invariant_for_aws_handlers() {
    use aws_sdk_sts::operation::get_session_token::GetSessionTokenOutput;
    use aws_sdk_sts::types::Credentials as StsCredentials;
    use aws_smithy_mocks::{mock, mock_client, RuleMode};
    use aws_smithy_types::DateTime as SmithyDateTime;
    use cloak_core::handlers::set_test_sts_factory;

    let _aws_lock = aws_sts_test_lock().await;

    let policy = r#"
        [default]
        action = "deny"
        [[secrets]]
        name = "AWS_LEAK"
        [secrets.tools.sign_request]
        allow = true
        [secrets.tools.mint_short_lived_token]
        allow = true
    "#;

    // Distinctive sentinel material so a leak is unambiguous.
    const AKID: &str = "AKIAQQQLEAKSENTINEL1";
    const SECRET: &str = "verysensitiveSecretMarker9999//+abcd";

    let factory: cloak_core::handlers::StsClientFactory = std::sync::Arc::new(
        |_akid: &str, _secret: &str, _region: &str| -> aws_sdk_sts::Client {
            let creds = StsCredentials::builder()
                .access_key_id("ASIATEMPMOCK")
                .secret_access_key("tempsecret")
                .session_token("tempsession==")
                .expiration(SmithyDateTime::from_secs(
                    chrono::Utc::now().timestamp() + 900,
                ))
                .build()
                .expect("creds");
            let rule = mock!(aws_sdk_sts::Client::get_session_token)
                .match_requests(|_req| true)
                .then_output(move || {
                    GetSessionTokenOutput::builder()
                        .credentials(creds.clone())
                        .build()
                });
            mock_client!(aws_sdk_sts, RuleMode::Sequential, &[&rule])
        },
    );
    let _prev = set_test_sts_factory(Some(factory));

    let (_pol, basename) = open_policy();
    let Some((socket, _dir, audit_path, shutdown, handle)) = spawn_daemon(basename, policy).await
    else {
        set_test_sts_factory(None);
        return;
    };
    let combined = format!("{AKID}:{SECRET}");
    let Some((mut stream, token)) =
        connect_init_unlock_seed(&socket, &[("AWS_LEAK", combined.as_str())]).await
    else {
        set_test_sts_factory(None);
        shutdown.notify_waiters();
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        return;
    };

    // 1. sign_request with aws-sigv4 — the SECRET portion of the secret
    // value must not appear in the response.
    let resp = rpc(
        &mut stream,
        Request {
            id: "s1".into(),
            method: "tool.sign_request".into(),
            params: json!({
                "secret_name": "AWS_LEAK",
                "scheme": "aws-sigv4",
                "method": "GET",
                "url": "https://example.amazonaws.com/",
                "aws_region": "us-east-1",
                "aws_service": "service",
            }),
            session_token: Some(token.clone()),
        },
    )
    .await;
    assert!(resp.error.is_none(), "sigv4 sign: {:?}", resp.error);
    let serialized = serde_json::to_string(&resp.result.unwrap()).unwrap();
    assert!(
        !serialized.contains(SECRET),
        "sigv4 response leaked secret material"
    );
    // The AKID is exposed as the Credential= component of Authorization
    // (this is normal SigV4 wire behavior). We do NOT assert it's
    // absent — that's the expected SigV4 design.

    // 2. mint_token aws-sts — neither AKID nor SECRET portion of the
    // parent credential may appear in the response or audit.
    let resp = rpc(
        &mut stream,
        Request {
            id: "m1".into(),
            method: "tool.mint_token".into(),
            params: json!({
                "secret_name": "AWS_LEAK",
                "kind": "aws-sts",
                "ttl_seconds": 900,
            }),
            session_token: Some(token.clone()),
        },
    )
    .await;
    assert!(resp.error.is_none(), "mint_token: {:?}", resp.error);
    let serialized = serde_json::to_string(&resp.result.unwrap()).unwrap();
    assert!(
        !serialized.contains(AKID),
        "mint_token response leaked AKID"
    );
    assert!(
        !serialized.contains(SECRET),
        "mint_token response leaked secret"
    );

    // 3. The audit log must not contain either the AKID or the secret.
    let raw_audit = std::fs::read_to_string(&audit_path).unwrap_or_default();
    assert!(
        !raw_audit.contains(AKID),
        "audit log leaked AKID: {raw_audit}"
    );
    assert!(
        !raw_audit.contains(SECRET),
        "audit log leaked secret: {raw_audit}"
    );

    drop(stream);
    shutdown.notify_waiters();
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    set_test_sts_factory(None);
}
