//! Daemon main loop, listener, and method dispatcher.
//!
//! Lifecycle:
//! 1. Resolve the socket path (`$XDG_RUNTIME_DIR/cloakd.sock` if set,
//!    else `${TMPDIR:-/tmp}/cloakd-$UID.sock`).
//! 2. If the path exists and a probe-connect is refused, remove the
//!    stale file. If the probe succeeds, refuse to start (a daemon is
//!    already running).
//! 3. `bind(2)` the UDS, chmod it to `0600`.
//! 4. Open the vault (it may be locked / uninitialized; that's fine).
//! 5. Install signal handlers for SIGINT/SIGTERM (graceful shutdown)
//!    and SIGHUP (logged "reload requested" — actual reload lives in
//!    the policy slice).
//! 6. Accept loop: per connection — peer-auth, dispatch, write replies.
//!
//! All `tracing` records carry `peer_pid`, `basename`, and `method`;
//! they never carry params, since params can contain passphrases or
//! secret values.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{Mutex, Notify};

use crate::audit::{AuditDraft, AuditLog, AuditResult, PeerSummary};
use crate::crypto::Secret;
use crate::egress::EgressClient;
use crate::error::{Error, Result};
use crate::handlers::HandlerCtx;
use crate::ipc::{read_request_json, rpc_error, write_response_json, Request, Response};
use crate::peer_auth::{self, PeerInfo, PeerKind, PeerPolicy};
use crate::policy::PolicyEngine;
use crate::session::{default_ttl, SessionRecord, SessionStore};
#[cfg(any(test, feature = "test-util"))]
use crate::vault::SecretKind;
use crate::vault::Vault;

// =========================================================================
// Public entry point
// =========================================================================

/// Run the daemon to completion. Returns when a SIGINT/SIGTERM is
/// received and all in-flight connections have finished.
pub async fn run() -> Result<()> {
    let socket_path = default_socket_path()?;
    tracing::info!(path = %socket_path.display(), "cloakd starting");
    let listener = bind_listener(&socket_path)?;

    let vault = Vault::open_or_create(&Vault::default_path()?)?;
    let policy_path = default_policy_path();
    let audit_path = default_audit_path()?;
    let policy_engine = PolicyEngine::from_path(&policy_path)?;
    let audit_log = AuditLog::open(&audit_path)?;
    let peer_policy = PeerPolicy::installed_v01()?;
    let egress = EgressClient::new()?;
    let ctx = Arc::new(DaemonCtx {
        vault: Mutex::new(vault),
        sessions: SessionStore::new(),
        policy: peer_policy,
        cli_basenames: vec!["cloak".to_string()],
        next_conn_id: AtomicU64::new(1),
        shutdown: Notify::new(),
        policy_engine: Mutex::new(policy_engine),
        audit_log: Mutex::new(audit_log),
        egress,
    });

    let shutdown_ctx = ctx.clone();
    tokio::spawn(async move {
        if let Err(e) = handle_signals(shutdown_ctx).await {
            tracing::warn!(error = %e, "signal handler exited");
        }
    });

    accept_loop(listener, ctx, &socket_path).await
}

// =========================================================================
// Socket path / bind
// =========================================================================

/// Resolve the daemon's UDS path per the IPC contract.
pub fn default_socket_path() -> Result<PathBuf> {
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR") {
        return Ok(PathBuf::from(rt).join("cloakd.sock"));
    }
    let tmp = std::env::var_os("TMPDIR").unwrap_or_else(|| std::ffi::OsString::from("/tmp"));
    let uid = peer_auth::our_uid();
    Ok(PathBuf::from(tmp).join(format!("cloakd-{uid}.sock")))
}

/// Bind a Unix listener at `path`, removing stale leftovers and
/// enforcing mode 0600. Refuses to start if a live daemon is already
/// listening on the path.
fn bind_listener(path: &Path) -> Result<UnixListener> {
    if path.exists() {
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(_alive) => {
                return Err(Error::Other(
                    "another cloakd is already listening on this socket",
                ));
            }
            Err(_) => {
                // Stale — clean it up.
                let _ = std::fs::remove_file(path);
            }
        }
    }
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let listener = UnixListener::bind(path)?;
    // chmod 0600 so only the daemon's own UID can connect (defense in
    // depth — `getpeereid` is the real gate).
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(listener)
}

// =========================================================================
// Daemon context
// =========================================================================

struct DaemonCtx {
    /// The single vault, behind a mutex (rusqlite::Connection is `!Sync`).
    vault: Mutex<Vault>,
    /// Live sessions. Tokens are revoked on disconnect.
    sessions: SessionStore,
    /// Peer-credential allowlist policy.
    policy: PeerPolicy,
    /// Basenames whose peers are treated as CLI peers (full vault surface).
    /// Default: `["cloak"]`. Overridable for tests.
    cli_basenames: Vec<String>,
    /// Monotonically-increasing per-connection ID (binds to session).
    next_conn_id: AtomicU64,
    /// Notified by the signal handler to begin shutdown.
    shutdown: Notify,
    /// Policy engine + rate-limit buckets. Locked per-call by handlers.
    policy_engine: Mutex<PolicyEngine>,
    /// Hash-chained audit log. Locked per-call by handlers.
    audit_log: Mutex<AuditLog>,
    /// Shared outbound HTTP client (built once at startup).
    egress: EgressClient,
}

/// Default policy file path from the platform config directory. Missing
/// file yields a default-deny policy via `PolicyEngine::from_path`.
fn default_policy_path() -> PathBuf {
    crate::policy::default_policy_path()
}

/// Default audit log path: `<data_dir>/cloak/audit.jsonl` (e.g.
/// `~/Library/Application Support/cloak/audit.jsonl` on macOS).
fn default_audit_path() -> Result<PathBuf> {
    let base = dirs::data_dir().ok_or(Error::Other("no data dir on this platform"))?;
    Ok(base.join("cloak").join("audit.jsonl"))
}

// =========================================================================
// Signal handling
// =========================================================================

async fn handle_signals(ctx: Arc<DaemonCtx>) -> Result<()> {
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;

    loop {
        tokio::select! {
            _ = sigint.recv() => {
                tracing::info!("SIGINT received, beginning graceful shutdown");
                ctx.shutdown.notify_waiters();
                return Ok(());
            }
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received, beginning graceful shutdown");
                ctx.shutdown.notify_waiters();
                return Ok(());
            }
            _ = sighup.recv() => {
                tracing::info!("SIGHUP: policy reload requested (not yet implemented)");
            }
        }
    }
}

// =========================================================================
// Accept loop
// =========================================================================

async fn accept_loop(
    listener: UnixListener,
    ctx: Arc<DaemonCtx>,
    socket_path: &Path,
) -> Result<()> {
    let our_uid = peer_auth::our_uid();
    loop {
        tokio::select! {
            biased;
            _ = ctx.shutdown.notified() => {
                tracing::info!("accept loop exiting");
                let _ = std::fs::remove_file(socket_path);
                return Ok(());
            }
            res = listener.accept() => {
                match res {
                    Ok((stream, _addr)) => {
                        let ctx2 = ctx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = serve_conn(stream, ctx2, our_uid).await {
                                tracing::debug!(error = %e, "connection exited with error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed");
                    }
                }
            }
        }
    }
}

// =========================================================================
// Per-connection serving
// =========================================================================

async fn serve_conn(stream: UnixStream, ctx: Arc<DaemonCtx>, our_uid: u32) -> Result<()> {
    // 1. Resolve and check peer credentials BEFORE issuing any token.
    //    On Linux we additionally open a pidfd for the peer here so we
    //    can wire up the per-connection process-death watcher below;
    //    on macOS the kqueue watcher is registered by PID directly so
    //    we just take the standard `peer_info_from_unix` path.
    #[cfg(all(unix, not(target_os = "macos")))]
    let (peer, peer_pidfd): (PeerInfo, std::os::fd::OwnedFd) = {
        // Linux: capture a race-free pidfd and bind its inode into the
        // session. If the kernel/runtime cannot provide SO_PEERPIDFD, fail
        // closed instead of issuing a session with weaker PID-reuse semantics.
        match peer_auth::peer_info_with_pidfd_linux(&stream) {
            Ok((p, pidfd)) => (p, pidfd),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "pidfd peer identity capture failed; closing connection"
                );
                return Ok(());
            }
        }
    };
    #[cfg(target_os = "macos")]
    let peer = match peer_auth::peer_info_from_unix(&stream) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "peer_info failed; closing connection");
            return Ok(());
        }
    };
    if let Err(e) = peer_auth::check(&peer, &ctx.policy, our_uid) {
        tracing::warn!(
            peer_pid = peer.pid,
            peer_uid = peer.uid,
            basename = peer.basename().unwrap_or_default(),
            "peer rejected: {e}"
        );
        return Ok(()); // close without writing
    }
    let conn_id = ctx.next_conn_id.fetch_add(1, Ordering::Relaxed);
    tracing::info!(
        conn_id,
        peer_pid = peer.pid,
        basename = peer.basename().unwrap_or_default(),
        "peer authenticated"
    );

    // 1b. Spawn a per-connection peer-exit watcher (kqueue NOTE_EXIT on
    //     macOS, pidfd POLLIN on Linux). If the peer dies — even before
    //     its socket FIN reaches us — we revoke every session bound to
    //     this peer's identity AND every session bound to this conn-id
    //     immediately, closing the PID-recycle window (threat model
    //     A8). `peer_exit` lets the read loop break out of `read` the
    //     instant the watcher fires. The task is aborted in the
    //     teardown path below if the read loop wins the race.
    let peer_exit = Arc::new(Notify::new());
    let peer_exited = Arc::new(AtomicBool::new(false));
    #[cfg(target_os = "macos")]
    let exit_watcher_task: Option<tokio::task::JoinHandle<()>> =
        match spawn_peer_exit_watcher(&ctx, &peer, conn_id, peer_exit.clone(), peer_exited.clone())
        {
            Ok(handle) => Some(handle),
            Err(e) => {
                tracing::warn!(
                    conn_id,
                    peer_pid = peer.pid,
                    error = %e,
                    "kqueue watcher setup failed; closing connection before handshake"
                );
                return Ok(());
            }
        };
    // Linux: spawn a pidfd-based watcher when we successfully captured
    // a pidfd (and the watcher's AsyncFd registration succeeds). Capture
    // itself is fail-closed above; watcher registration failure revokes
    // eagerly inside `spawn_peer_exit_watcher`.
    #[cfg(all(unix, not(target_os = "macos")))]
    let exit_watcher_task: Option<tokio::task::JoinHandle<()>> = match spawn_peer_exit_watcher(
        &ctx,
        &peer,
        peer_pidfd,
        conn_id,
        peer_exit.clone(),
        peer_exited.clone(),
    ) {
        Ok(handle) => Some(handle),
        Err(e) => {
            tracing::warn!(
                conn_id,
                peer_pid = peer.pid,
                error = %e,
                "pidfd watcher setup failed; closing connection before handshake"
            );
            return Ok(());
        }
    };

    // 2. Split the stream so we can read & write concurrently if we
    //    ever need to. v0.1 is request/response, so we just borrow.
    let (mut rd, mut wr) = stream.into_split();

    // 3. Connection loop. The peer-exit watcher revokes session tokens
    //    immediately on peer death and also forces this loop closed.
    //    An inherited socket fd must not be able to issue a fresh
    //    handshake after the original peer process has exited.
    loop {
        if peer_exited.load(Ordering::SeqCst) {
            tracing::debug!(conn_id, "peer-exit watcher fired; closing connection");
            break;
        }

        let read_result = tokio::select! {
            biased;
            _ = peer_exit.notified() => {
                tracing::debug!(conn_id, "peer-exit notification received; closing connection");
                break;
            }
            r = read_request_json(&mut rd) => r,
        };

        if peer_exited.load(Ordering::SeqCst) {
            tracing::debug!(conn_id, "peer exited during frame read; closing connection");
            break;
        }

        let req = match read_result {
            Ok(r) => r,
            Err(Error::IpcFraming(m)) if m.contains("short read") => {
                tracing::debug!(conn_id, "peer closed before sending a frame; short read");
                break;
            }
            Err(e) => {
                tracing::debug!(conn_id, error = %e, "read_request_json error; closing");
                let resp = Response::err(
                    "0",
                    rpc_error("invalid-params", format!("frame error: {e}")),
                );
                let _ = write_response_json(&mut wr, &resp).await;
                break;
            }
        };

        let resp = dispatch(&ctx, &peer, conn_id, req).await;
        if peer_exited.load(Ordering::SeqCst) {
            tracing::debug!(
                conn_id,
                "peer exited during request handling; suppressing response"
            );
            break;
        }
        if write_response_json(&mut wr, &resp).await.is_err() {
            break;
        }
    }

    // 4. Tear down: revoke any session tokens bound to this conn, and
    //    abort the exit-watcher task if it's still alive.
    if let Some(handle) = exit_watcher_task {
        handle.abort();
    }
    ctx.sessions.revoke_by_conn(conn_id).await;
    tracing::debug!(conn_id, "connection closed; sessions revoked");
    Ok(())
}

/// macOS: spawn a [`peer_auth::PeerExitWatcher`] that revokes every
/// session bound to `conn_id` (and the captured peer identity) the
/// moment the kernel reports the peer has exited. Returns the task
/// handle so the connection-teardown path can abort it on normal
/// close. The Linux companion below mirrors this shape with a pidfd.
#[cfg(target_os = "macos")]
fn spawn_peer_exit_watcher(
    ctx: &Arc<DaemonCtx>,
    peer: &PeerInfo,
    conn_id: u64,
    peer_exit: Arc<Notify>,
    peer_exited: Arc<AtomicBool>,
) -> Result<tokio::task::JoinHandle<()>> {
    let pid = peer.pid;
    let identity = peer.identity.clone();
    let watcher = match peer_auth::PeerExitWatcher::new(pid) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(
                conn_id,
                peer_pid = pid,
                error = %e,
                "kqueue exit watcher could not register"
            );
            return Err(e);
        }
    };
    let sessions = ctx.sessions.clone_handle();
    Ok(tokio::spawn(async move {
        match watcher.wait().await {
            Ok(()) => {
                tracing::info!(
                    conn_id,
                    peer_pid = pid,
                    "peer exited; revoking sessions for this connection"
                );
            }
            Err(e) => {
                tracing::warn!(
                    conn_id,
                    peer_pid = pid,
                    error = %e,
                    "kqueue exit watcher errored; revoking sessions defensively"
                );
            }
        }
        peer_exited.store(true, Ordering::SeqCst);
        if let Some(id) = identity.as_ref() {
            sessions.revoke_by_identity(id).await;
        }
        sessions.revoke_by_conn(conn_id).await;
        peer_exit.notify_waiters();
    }))
}

/// Linux: spawn a [`peer_auth::linux::PidfdWatcher`] that revokes every
/// session bound to `conn_id` (and the captured pidfd-inode identity)
/// the moment the kernel signals `POLLIN` on the peer's pidfd. Mirrors
/// the macOS arm above: same identity-then-conn-id revocation order,
/// same `peer_exit` notify so the read loop unblocks immediately.
#[cfg(all(unix, not(target_os = "macos")))]
fn spawn_peer_exit_watcher(
    ctx: &Arc<DaemonCtx>,
    peer: &PeerInfo,
    peer_pidfd: std::os::fd::OwnedFd,
    conn_id: u64,
    peer_exit: Arc<Notify>,
    peer_exited: Arc<AtomicBool>,
) -> Result<tokio::task::JoinHandle<()>> {
    let pid = peer.pid;
    let identity = peer.identity.clone();
    let watcher = match peer_auth::linux::PidfdWatcher::new(peer_pidfd, pid) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(
                conn_id,
                peer_pid = pid,
                error = %e,
                "pidfd watcher could not register with tokio reactor"
            );
            return Err(e);
        }
    };
    let sessions = ctx.sessions.clone_handle();
    Ok(tokio::spawn(async move {
        match watcher.wait().await {
            Ok(()) => {
                tracing::info!(
                    conn_id,
                    peer_pid = pid,
                    "peer exited; revoking sessions for this connection"
                );
            }
            Err(e) => {
                tracing::warn!(
                    conn_id,
                    peer_pid = pid,
                    error = %e,
                    "pidfd watcher errored; revoking sessions defensively"
                );
            }
        }
        peer_exited.store(true, Ordering::SeqCst);
        if let Some(id) = identity.as_ref() {
            sessions.revoke_by_identity(id).await;
        }
        sessions.revoke_by_conn(conn_id).await;
        peer_exit.notify_waiters();
    }))
}

// =========================================================================
// Dispatcher
// =========================================================================

/// Methods callable only by the CLI peer (basename == `cloak`).
fn is_cli_only_method(m: &str) -> bool {
    matches!(m, "vault.show" | "vault.unlock" | "vault.lock") || is_test_only_vault_write_method(m)
}

#[cfg(any(test, feature = "test-util"))]
fn is_test_only_vault_write_method(m: &str) -> bool {
    matches!(
        m,
        "vault.initialize" | "vault.add" | "vault.set" | "vault.rm"
    )
}

#[cfg(not(any(test, feature = "test-util")))]
fn is_test_only_vault_write_method(_m: &str) -> bool {
    false
}

fn known_method(m: &str) -> bool {
    matches!(
        m,
        "cli.handshake"
            | "mcp.handshake"
            | "vault.is_initialized"
            | "vault.list"
            | "vault.get_metadata"
            | "vault.status"
            | "vault.unlock"
            | "vault.lock"
            | "vault.show"
            | "tool.sign_request"
            | "tool.proxy_http"
            | "tool.mint_token"
            | "tool.query_audit"
    ) || is_test_only_vault_write_method(m)
}

async fn dispatch(ctx: &Arc<DaemonCtx>, peer: &PeerInfo, conn_id: u64, req: Request) -> Response {
    let id = req.id.clone();
    let method = req.method.clone();

    // Log peer pid + basename + method. Never log params.
    tracing::debug!(
        conn_id,
        peer_pid = peer.pid,
        basename = peer.basename().unwrap_or_default(),
        method = %method,
        "request"
    );

    // Unknown method short-circuit (handshake check is below; both
    // `cli.handshake` and `mcp.handshake` are in `known_method`).
    if !known_method(&method) {
        return Response::err(
            id,
            rpc_error("unknown-method", format!("unknown method: {method}")),
        );
    }

    // Handshake methods bypass the session-token check.
    if method == "cli.handshake" || method == "mcp.handshake" {
        return match handle_handshake(ctx, peer, conn_id, &method).await {
            Ok(v) => Response::ok(id, v),
            Err(e) => Response::err(id, (&e).into()),
        };
    }

    // Every other method requires a session token bound to this conn.
    let token = match req.session_token.as_deref() {
        Some(t) if !t.is_empty() => t,
        _ => {
            return Response::err(id, rpc_error("session-expired", "missing session token"));
        }
    };
    let session = match ctx
        .sessions
        .validate_with_identity(token, conn_id, peer.identity.as_ref())
        .await
    {
        Ok(rec) => rec,
        Err(_) => {
            return Response::err(
                id,
                rpc_error("session-expired", "invalid or expired session"),
            );
        }
    };

    match dispatch_method(ctx, peer, &session, &method, &req.params).await {
        Ok(v) => Response::ok(id, v),
        Err(DispatchError::VaultLocked) => Response::err(
            id,
            rpc_error("vault-locked", "vault is locked; run `cloak unlock`"),
        ),
        Err(DispatchError::Typed(e)) => Response::err(id, (&e).into()),
    }
}

/// Dispatch-internal error type. We carry `VaultLocked` separately so
/// the wire layer can emit the dedicated `vault-locked` symbolic code
/// without expanding the public `Error` enum (owned by the core agent).
enum DispatchError {
    /// The requested method needs an unlocked vault.
    VaultLocked,
    /// Any other typed error from the vault / handlers.
    Typed(Error),
}

impl From<Error> for DispatchError {
    fn from(e: Error) -> Self {
        DispatchError::Typed(e)
    }
}

async fn handle_handshake(
    ctx: &Arc<DaemonCtx>,
    peer: &PeerInfo,
    conn_id: u64,
    method: &str,
) -> Result<Value> {
    let basename = peer.basename();
    let peer_kind = if basename
        .as_ref()
        .is_some_and(|b| ctx.cli_basenames.iter().any(|cli| cli == b))
    {
        PeerKind::Cli
    } else if peer.kind() == PeerKind::Mcp
        || basename.as_ref().is_some_and(|b| {
            ctx.policy
                .allowed_basenames
                .iter()
                .any(|allowed| allowed == b)
        })
    {
        PeerKind::Mcp
    } else {
        PeerKind::Other
    };
    match (method, peer_kind) {
        ("cli.handshake", PeerKind::Cli) | ("mcp.handshake", PeerKind::Mcp) => {}
        _ => {
            tracing::warn!(
                peer_pid = peer.pid,
                basename = ?peer.basename(),
                method,
                "peer kind does not match requested handshake"
            );
            return Err(Error::PeerNotTrusted);
        }
    }
    if peer.identity.is_none() {
        tracing::error!(
            peer_pid = peer.pid,
            basename = ?peer.basename(),
            "peer identity unavailable; refusing to issue session"
        );
        return Err(Error::PeerNotTrusted);
    }
    let tok = ctx.sessions.issue(peer, conn_id, default_ttl()).await?;
    Ok(json!({ "session_token": tok.0 }))
}

async fn audit_dispatch(
    ctx: &Arc<DaemonCtx>,
    draft: AuditDraft,
) -> std::result::Result<(), DispatchError> {
    let mut audit = ctx.audit_log.lock().await;
    audit
        .append(draft)
        .map(|_| ())
        .map_err(|_| DispatchError::Typed(Error::Other("audit append failed")))
}

async fn dispatch_method(
    ctx: &Arc<DaemonCtx>,
    peer: &PeerInfo,
    session: &SessionRecord,
    method: &str,
    params: &Value,
) -> std::result::Result<Value, DispatchError> {
    // Enforce CLI-only methods. The session is bound at handshake to
    // the peer's basename; we trust that record here.
    if is_cli_only_method(method)
        && !ctx
            .cli_basenames
            .iter()
            .any(|b| b == &session.peer_basename)
    {
        return Err(Error::PeerNotTrusted.into());
    }

    match method {
        // ---- vault: read-only metadata (CLI + MCP) ----
        "vault.is_initialized" => {
            let v = ctx.vault.lock().await;
            Ok(json!({ "initialized": v.is_initialized()? }))
        }
        "vault.list" => {
            let v = ctx.vault.lock().await;
            require_unlocked(&v)?;
            let rows = v.list()?;
            let secrets: Vec<Value> = rows
                .into_iter()
                .map(|m| {
                    json!({
                        "name": m.name,
                        "kind": m.kind.as_str(),
                        "tags": m.tags,
                        "created_at": m.created_at.to_rfc3339(),
                        "updated_at": m.updated_at.to_rfc3339(),
                        "version": m.version,
                    })
                })
                .collect();
            Ok(json!({ "secrets": secrets }))
        }
        "vault.get_metadata" => {
            let p: NameParams = parse_params(params)?;
            let v = ctx.vault.lock().await;
            require_unlocked(&v)?;
            let m = v.get_metadata(&p.name)?;
            Ok(json!({
                "name": m.name,
                "kind": m.kind.as_str(),
                "tags": m.tags,
                "created_at": m.created_at.to_rfc3339(),
                "updated_at": m.updated_at.to_rfc3339(),
                "version": m.version,
            }))
        }
        "vault.status" => {
            let v = ctx.vault.lock().await;
            let s = v.status()?;
            Ok(json!({
                "path": s.path.display().to_string(),
                "record_count": s.record_count,
                "kdf_params": {
                    "mem_kib": s.kdf_params.mem_kib,
                    "t_cost": s.kdf_params.t_cost,
                    "p_cost": s.kdf_params.p_cost,
                },
                "format_version": s.format_version,
                "locked": s.locked,
            }))
        }

        // ---- vault: test-only management fixture methods ----
        //
        // Production builds do not expose vault initialization or mutation
        // over IPC; the real CLI opens the vault file directly for these
        // operations. Integration tests keep these cfg-gated methods so
        // they can seed a daemon-owned vault without duplicating daemon
        // startup internals.
        #[cfg(any(test, feature = "test-util"))]
        "vault.initialize" => {
            let p: PassphraseParams = parse_params(params)?;
            let mut v = ctx.vault.lock().await;
            let init = v.initialize(&Secret::new(p.passphrase))?;
            Ok(json!({
                "kdf_params": {
                    "mem_kib": init.kdf_params.mem_kib,
                    "t_cost": init.kdf_params.t_cost,
                    "p_cost": init.kdf_params.p_cost,
                }
            }))
        }
        #[cfg(any(test, feature = "test-util"))]
        "vault.add" => {
            let p: AddParams = parse_params(params)?;
            let v = ctx.vault.lock().await;
            require_unlocked(&v)?;
            v.add(
                &p.name,
                SecretKind::from_str_lossy(&p.kind),
                p.tags,
                &Secret::new(p.value),
            )?;
            let md = v.get_metadata(&p.name)?;
            Ok(json!({ "ok": true, "version": md.version }))
        }
        #[cfg(any(test, feature = "test-util"))]
        "vault.set" => {
            let p: SetParams = parse_params(params)?;
            let v = ctx.vault.lock().await;
            require_unlocked(&v)?;
            v.set(&p.name, &Secret::new(p.value))?;
            let md = v.get_metadata(&p.name)?;
            Ok(json!({ "ok": true, "version": md.version }))
        }
        #[cfg(any(test, feature = "test-util"))]
        "vault.rm" => {
            let p: NameParams = parse_params(params)?;
            let v = ctx.vault.lock().await;
            require_unlocked(&v)?;
            v.rm(&p.name)?;
            Ok(json!({ "ok": true }))
        }

        // ---- vault: session management (CLI only) ----
        "vault.unlock" => {
            let p: PassphraseParams = parse_params(params)?;
            let mut v = ctx.vault.lock().await;
            v.unlock(&Secret::new(p.passphrase))?;
            Ok(json!({ "ok": true }))
        }
        "vault.lock" => {
            let mut v = ctx.vault.lock().await;
            v.lock();
            Ok(json!({ "ok": true }))
        }
        "vault.show" => {
            let p: ShowParams = parse_params(params)?;
            let summary = peer_summary_for(peer, session);
            // Server-side biometric / user-presence gate. The daemon
            // itself fires the Touch ID (macOS) / polkit (Linux) prompt
            // before any plaintext leaves the vault. No client-supplied
            // flag may downgrade this requirement: a same-UID process
            // that connects to the socket directly must face the same
            // OS prompt as the CLI path.
            let reason = format!("Reveal secret '{}' from Cloak vault", p.name);
            let confirmed =
                tokio::task::spawn_blocking(move || crate::biometric::run_authenticate(&reason))
                    .await
                    .map_err(|_| DispatchError::Typed(Error::Other("biometric task panicked")))?
                    .map_err(|_| DispatchError::Typed(Error::BiometricFailed))?;
            if !confirmed {
                audit_dispatch(
                    ctx,
                    AuditDraft {
                        peer: summary,
                        tool: "vault.show".to_string(),
                        secret: Some(p.name),
                        target: None,
                        result: AuditResult::Denied,
                        note: Some("user-presence denied".to_string()),
                    },
                )
                .await?;
                return Err(DispatchError::Typed(Error::BiometricFailed));
            }
            let s = {
                let v = ctx.vault.lock().await;
                require_unlocked(&v)?;
                match v.show(&p.name) {
                    Ok(s) => s,
                    Err(e) => {
                        audit_dispatch(
                            ctx,
                            AuditDraft {
                                peer: summary,
                                tool: "vault.show".to_string(),
                                secret: Some(p.name),
                                target: None,
                                result: AuditResult::Error,
                                note: Some("vault.show failed".to_string()),
                            },
                        )
                        .await?;
                        return Err(DispatchError::Typed(e));
                    }
                }
            };
            audit_dispatch(
                ctx,
                AuditDraft {
                    peer: summary,
                    tool: "vault.show".to_string(),
                    secret: Some(p.name),
                    target: None,
                    result: AuditResult::Ok,
                    note: Some("plaintext reveal".to_string()),
                },
            )
            .await?;
            Ok(json!({ "value": s.expose_secret() }))
        }

        // ---- privileged tool surface ----
        "tool.sign_request" => {
            let summary = peer_summary_for(peer, session);
            let hctx = HandlerCtx {
                vault: &ctx.vault,
                policy: &ctx.policy_engine,
                audit: &ctx.audit_log,
                egress: &ctx.egress,
                peer: &summary,
            };
            crate::handlers::sign_request(&hctx, params)
                .await
                .map_err(DispatchError::from)
        }
        "tool.proxy_http" => {
            let summary = peer_summary_for(peer, session);
            let hctx = HandlerCtx {
                vault: &ctx.vault,
                policy: &ctx.policy_engine,
                audit: &ctx.audit_log,
                egress: &ctx.egress,
                peer: &summary,
            };
            crate::handlers::proxy_http(&hctx, params)
                .await
                .map_err(DispatchError::from)
        }
        "tool.mint_token" => {
            let summary = peer_summary_for(peer, session);
            let hctx = HandlerCtx {
                vault: &ctx.vault,
                policy: &ctx.policy_engine,
                audit: &ctx.audit_log,
                egress: &ctx.egress,
                peer: &summary,
            };
            crate::handlers::mint_token(&hctx, params)
                .await
                .map_err(DispatchError::from)
        }
        "tool.query_audit" => {
            let summary = peer_summary_for(peer, session);
            let hctx = HandlerCtx {
                vault: &ctx.vault,
                policy: &ctx.policy_engine,
                audit: &ctx.audit_log,
                egress: &ctx.egress,
                peer: &summary,
            };
            crate::handlers::query_audit(&hctx, params)
                .await
                .map_err(DispatchError::from)
        }

        // `known_method` was checked above; this branch is unreachable.
        _ => Err(Error::Other("dispatch fell through").into()),
    }
}

// =========================================================================
// Param structs
// =========================================================================

#[derive(serde::Deserialize)]
struct PassphraseParams {
    passphrase: String,
}

#[derive(serde::Deserialize)]
struct NameParams {
    name: String,
}

#[cfg(any(test, feature = "test-util"))]
#[derive(serde::Deserialize)]
struct AddParams {
    name: String,
    kind: String,
    #[serde(default)]
    tags: Vec<String>,
    value: String,
}

#[cfg(any(test, feature = "test-util"))]
#[derive(serde::Deserialize)]
struct SetParams {
    name: String,
    value: String,
}

/// Parameters for `vault.show`.
///
/// Legacy clients may still send `skip_biometric`; it is accepted for
/// wire compatibility but ignored. Plaintext reveal is always gated by
/// the daemon's own OS-level user-presence prompt.
#[derive(serde::Deserialize)]
struct ShowParams {
    name: String,
    #[serde(default)]
    _skip_biometric: bool,
}

fn parse_params<T: serde::de::DeserializeOwned>(
    v: &Value,
) -> std::result::Result<T, DispatchError> {
    serde_json::from_value(v.clone())
        .map_err(|_| DispatchError::Typed(Error::IpcFraming("invalid params")))
}

/// Build the audit `PeerSummary` from the connection's peer info plus the
/// session's recorded basename. We prefer the session's basename (it was
/// recorded at handshake time, after the peer-auth gate) but fall back to
/// `PeerInfo::basename()` if for some reason it's empty.
fn peer_summary_for(peer: &PeerInfo, session: &SessionRecord) -> PeerSummary {
    let basename = if !session.peer_basename.is_empty() {
        session.peer_basename.clone()
    } else {
        peer.basename().unwrap_or_default()
    };
    let code_sig_hex = peer.code_sig_hash.map(hex::encode);
    PeerSummary {
        pid: peer.pid,
        basename,
        code_sig_hex,
    }
}

fn require_unlocked(v: &Vault) -> std::result::Result<(), DispatchError> {
    if !v.is_unlocked() {
        return Err(DispatchError::VaultLocked);
    }
    Ok(())
}

// =========================================================================
// Test entry point
// =========================================================================

/// Run the daemon against a pre-bound listener, an explicit vault path,
/// and an externally-owned shutdown signal. Used by integration tests.
///
/// `cli_basenames` is the set of peer basenames that should receive
/// full CLI privileges (production: `["cloak"]`).
///
/// `policy_path` and `audit_path` are explicit so tests can point them at
/// per-test temp files. If `policy_path` does not exist, the policy
/// engine starts in default-deny mode (matches production).
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub async fn run_with(
    listener: UnixListener,
    vault_path: PathBuf,
    socket_path: PathBuf,
    policy: PeerPolicy,
    cli_basenames: Vec<String>,
    shutdown: Arc<Notify>,
    policy_path: PathBuf,
    audit_path: PathBuf,
) -> Result<()> {
    let vault = Vault::open_or_create(&vault_path)?;
    let policy_engine = PolicyEngine::from_path(&policy_path)?;
    let audit_log = AuditLog::open(&audit_path)?;
    let egress = EgressClient::new()?;
    let ctx = Arc::new(DaemonCtx {
        vault: Mutex::new(vault),
        sessions: SessionStore::new(),
        policy,
        cli_basenames,
        next_conn_id: AtomicU64::new(1),
        shutdown: Notify::new(),
        policy_engine: Mutex::new(policy_engine),
        audit_log: Mutex::new(audit_log),
        egress,
    });

    let bridge_ctx = ctx.clone();
    let bridge = tokio::spawn(async move {
        shutdown.notified().await;
        bridge_ctx.shutdown.notify_waiters();
    });

    let res = accept_loop(listener, ctx, &socket_path).await;
    bridge.abort();
    res
}
