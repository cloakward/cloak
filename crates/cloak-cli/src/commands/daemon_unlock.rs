//! `cloak daemon-unlock` — push the vault passphrase into the running
//! daemon so MCP peers can serve `vault.list` / `tool.*` requests.
//!
//! ## Why this exists
//!
//! In v0.1 the CLI is a *library client* of `cloak-core`: every
//! `cloak {init,add,set,get,list,rm,show,status}` opens the SQLite vault
//! file directly. The privileged daemon (`cloakd`) keeps its own
//! in-memory `Vault`, which starts **locked**. MCP peers can only call
//! the daemon, so until somebody unlocks the daemon's in-memory state,
//! the model surface returns `vault-locked`.
//!
//! `cloak daemon-unlock` is the smallest possible bridge: it speaks
//! the IPC protocol as a CLI peer, performs `cli.handshake`, and then
//! forwards a `vault.unlock` with the user's passphrase. Once the
//! daemon's vault is unlocked, MCP requests can flow.
//!
//! In v1.x the CLI will move *fully* onto IPC and this command will
//! become an internal detail of `cloak unlock`. For v0.1 it's a
//! deliberately separate step so the smoke test can demonstrate the
//! end-to-end flow without conflating "open the file on disk" with
//! "tell the daemon the passphrase".

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, Result};
use serde_json::{json, Value};

use crate::commands::{Context, SystemError};
use crate::prompt;

const FRAME_MAX: usize = 4 * 1024 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Default UDS path used by the daemon. Mirrors `cloak_core::daemon::default_socket_path`
/// without taking a dependency on the (Unix-only) function.
fn default_socket_path() -> PathBuf {
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(rt).join("cloakd.sock");
    }
    let tmp = std::env::var_os("TMPDIR").unwrap_or_else(|| std::ffi::OsString::from("/tmp"));
    let uid = unsafe { libc::getuid() };
    PathBuf::from(tmp).join(format!("cloakd-{uid}.sock"))
}

pub fn run(_ctx: &Context) -> Result<()> {
    let sock = default_socket_path();

    // Before sending any passphrase: verify the socket file is actually owned by us
    // and not group/world-writable. Defense against a same-UID stale-socket race
    // where a malicious process unlinks /tmp/cloakd-$UID.sock after cloakd crashes
    // and binds its own listener at the same path.
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(&sock).map_err(|e| {
            SystemError::boxed(format!(
                "could not stat cloakd socket {}: {e}",
                sock.display()
            ))
        })?;
        let mode = meta.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(SystemError::boxed(format!(
                "cloakd socket {} has unsafe mode {:o} (group/world bits set); refusing to send passphrase",
                sock.display(),
                mode
            )));
        }
        let our_uid = unsafe { libc::geteuid() };
        if meta.uid() != our_uid {
            return Err(SystemError::boxed(format!(
                "cloakd socket {} is owned by uid {} not us ({}); refusing to send passphrase",
                sock.display(),
                meta.uid(),
                our_uid
            )));
        }
    }

    let mut stream = UnixStream::connect(&sock).map_err(|e| {
        SystemError::boxed(format!(
            "could not connect to cloakd at {}: {e} (is the daemon running?)",
            sock.display()
        ))
    })?;
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .context("set socket read timeout")?;

    // 1. Handshake.
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

    // 2. Read passphrase (env override honored by `prompt`).
    let pass = prompt::prompt_passphrase("vault passphrase: ")?;

    // 3. Send vault.unlock.
    let unlock_id = uuid::Uuid::new_v4().to_string();
    let req = json!({
        "id": unlock_id,
        "method": "vault.unlock",
        "params": { "passphrase": pass.expose_secret() },
        "session_token": token,
    });
    write_frame(&mut stream, &req)?;
    let resp = read_frame(&mut stream)?;
    if let Some(err) = resp.get("error") {
        anyhow::bail!("daemon refused unlock: {}", err);
    }
    println!("daemon vault unlocked");
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
