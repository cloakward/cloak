//! Shared CLI-to-`cloakd` IPC helper.
//!
//! Several CLI subcommands need to speak the privileged daemon's IPC
//! protocol as a CLI peer: `daemon-unlock` pushes the vault passphrase,
//! and `allow` / `deny` trigger a live policy reload. They all follow the
//! same shape:
//!
//! 1. Resolve the daemon's Unix-domain socket path.
//! 2. Verify the socket file is owned by us and not group/world-writable
//!    (defends against a same-UID stale-socket race where a hostile
//!    process binds its own listener at the well-known path).
//! 3. Connect, then verify the *connected* process is the expected
//!    sibling `cloakd` binary running under our uid (peer-credential
//!    auth).
//! 4. Perform `cli.handshake` to obtain a session token.
//! 5. Send the requested method with that token and return its `result`.
//!
//! [`call_daemon`] encapsulates steps 1 through 5. If the socket is
//! absent or the connect fails (the daemon isn't running), it returns a
//! [`DaemonDown`] error so callers can treat "daemon down" as non-fatal
//! (e.g. a policy edit is still persisted to disk and applies on next
//! daemon start).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, Result};
use cloak_core::peer_auth;
use serde_json::{json, Value};

use crate::commands::{daemon, SystemError};

pub(crate) const FRAME_MAX: usize = 4 * 1024 * 1024;
pub(crate) const READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Error returned when the daemon socket is absent or the connect fails.
/// Callers can downcast to treat "daemon not running" as non-fatal.
#[derive(Debug, thiserror::Error)]
#[error("daemon not running: {message}")]
pub(crate) struct DaemonDown {
    message: String,
}

impl DaemonDown {
    fn boxed(msg: impl Into<String>) -> anyhow::Error {
        anyhow::Error::new(Self {
            message: msg.into(),
        })
    }
}

/// Returns true if `err` indicates the daemon was not reachable (socket
/// absent or connect refused), as opposed to a protocol / auth failure.
pub(crate) fn is_daemon_down(err: &anyhow::Error) -> bool {
    err.downcast_ref::<DaemonDown>().is_some()
}

/// Default UDS path used by the daemon. Mirrors
/// `cloak_core::daemon::default_socket_path` without taking a dependency
/// on the (Unix-only) function.
pub(crate) fn default_socket_path() -> PathBuf {
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(rt).join("cloakd.sock");
    }
    let tmp = std::env::var_os("TMPDIR").unwrap_or_else(|| std::ffi::OsString::from("/tmp"));
    let uid = unsafe { libc::getuid() };
    PathBuf::from(tmp).join(format!("cloakd-{uid}.sock"))
}

/// Connect to the running `cloakd`, perform `cli.handshake`, then send
/// `method` with the session token. Returns the method's `result` value.
///
/// If the daemon socket is absent or the connect fails, returns a
/// [`DaemonDown`] error (detectable via [`is_daemon_down`]) so the caller
/// can treat the daemon as optional.
///
/// All the peer-credential and socket-safety checks from `daemon-unlock`
/// run before any bytes are sent; do not weaken them.
pub(crate) fn call_daemon(method: &str, params: Value) -> Result<Value> {
    let sock = default_socket_path();

    // If the socket file doesn't exist at all, the daemon isn't running.
    // Surface that as a distinct, recoverable error.
    if !sock.exists() {
        return Err(DaemonDown::boxed(format!(
            "no cloakd socket at {}",
            sock.display()
        )));
    }

    // Before sending anything: verify the socket file is actually owned by
    // us and not group/world-writable. Defense against a same-UID
    // stale-socket race where a malicious process unlinks
    // /tmp/cloakd-$UID.sock after cloakd crashes and binds its own
    // listener at the same path.
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(&sock).map_err(|e| {
            SystemError::boxed(format!("could not stat cloakd socket {}: {e}", sock.display()))
        })?;
        let mode = meta.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(SystemError::boxed(format!(
                "cloakd socket {} has unsafe mode {:o} (group/world bits set); refusing to talk to it",
                sock.display(),
                mode
            )));
        }
        let our_uid = unsafe { libc::geteuid() };
        if meta.uid() != our_uid {
            return Err(SystemError::boxed(format!(
                "cloakd socket {} is owned by uid {} not us ({}); refusing to talk to it",
                sock.display(),
                meta.uid(),
                our_uid
            )));
        }
    }

    let mut stream = match UnixStream::connect(&sock) {
        Ok(s) => s,
        Err(e) => {
            return Err(DaemonDown::boxed(format!(
                "could not connect to cloakd at {}: {e}",
                sock.display()
            )));
        }
    };
    verify_connected_daemon(&stream)?;
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .context("set socket read timeout")?;

    // 1. Handshake to obtain a session token.
    let handshake_id = uuid::Uuid::new_v4().to_string();
    let req = json!({
        "id": handshake_id,
        "method": "cli.handshake",
        "params": {},
    });
    write_frame(&mut stream, &req)?;
    let resp = read_frame(&mut stream)?;
    if let Some(err) = resp.get("error") {
        anyhow::bail!("daemon refused handshake: {}", err);
    }
    let token = resp
        .get("result")
        .and_then(|r| r.get("session_token"))
        .and_then(|t| t.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing session_token in handshake response"))?
        .to_string();

    // 2. Send the requested method with the session token.
    let call_id = uuid::Uuid::new_v4().to_string();
    let req = json!({
        "id": call_id,
        "method": method,
        "params": params,
        "session_token": token,
    });
    write_frame(&mut stream, &req)?;
    let resp = read_frame(&mut stream)?;
    if let Some(err) = resp.get("error") {
        anyhow::bail!("daemon refused {method}: {}", err);
    }
    Ok(resp.get("result").cloned().unwrap_or(Value::Null))
}

fn verify_connected_daemon(stream: &UnixStream) -> Result<()> {
    let peer = peer_auth::peer_info_from_std_unix(stream).map_err(|e| {
        SystemError::boxed(format!(
            "could not verify connected cloakd process before sending data: {e}"
        ))
    })?;

    let our_uid = unsafe { libc::geteuid() };
    if peer.uid != our_uid {
        return Err(SystemError::boxed(format!(
            "connected daemon uid {} does not match our uid {}; refusing to send data",
            peer.uid, our_uid
        )));
    }

    let basename = peer.basename().unwrap_or_default();
    if basename != "cloakd" {
        return Err(SystemError::boxed(format!(
            "connected process is {:?}, not cloakd; refusing to send data",
            basename
        )));
    }

    let peer_path = peer
        .binary_path
        .as_ref()
        .ok_or_else(|| SystemError::boxed("could not resolve connected cloakd path"))?;
    let peer_path = peer_path
        .canonicalize()
        .with_context(|| format!("canonicalize connected cloakd path {}", peer_path.display()))?;
    let expected_daemon = daemon::resolve_cloakd_bin().and_then(|p| {
        p.canonicalize()
            .with_context(|| format!("canonicalize expected cloakd path {}", p.display()))
    })?;
    if peer_path != expected_daemon {
        return Err(SystemError::boxed(format!(
            "connected cloakd path {} does not match expected sibling {}; refusing to send data",
            peer_path.display(),
            expected_daemon.display()
        )));
    }

    Ok(())
}

fn write_frame(stream: &mut UnixStream, body: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(body)?;
    if bytes.len() > FRAME_MAX {
        anyhow::bail!("outgoing frame exceeds 4 MiB");
    }
    let len = (bytes.len() as u32).to_le_bytes();
    stream.write_all(&len).context("write length prefix")?;
    stream.write_all(&bytes).context("write frame body")?;
    Ok(())
}

fn read_frame(stream: &mut UnixStream) -> Result<Value> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .context("read length prefix")?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > FRAME_MAX {
        anyhow::bail!("incoming frame exceeds 4 MiB");
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).context("read frame body")?;
    Ok(serde_json::from_slice(&body)?)
}
