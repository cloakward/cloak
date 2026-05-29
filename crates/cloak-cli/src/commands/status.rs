//! `cloak status` — print vault metadata and daemon unlock state if reachable.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use anyhow::{Context as _, Result};
use cloak_core::vault::Vault;
use serde_json::{json, Value};

use super::{daemon, open_vault, Context, SystemError};

const FRAME_MAX: usize = 4 * 1024 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) enum DaemonVaultState {
    NotRunning,
    Known { locked: bool },
    Unknown(String),
}

/// Print a one-screen summary of the vault. If the vault is not yet
/// initialized we print "uninitialized" and return a system-level error
/// so the exit code is `2`.
pub fn run(ctx: &Context) -> Result<()> {
    let vault = open_vault(ctx)?;
    if !vault.is_initialized()? {
        println!("path:           {}", ctx.vault_path.display());
        println!("status:         uninitialized");
        return Err(SystemError::boxed("vault uninitialized"));
    }

    let s: cloak_core::vault::VaultStatus = Vault::status(&vault)?;
    println!("path:           {}", s.path.display());
    println!("format version: {}", s.format_version);
    println!("records:        {}", s.record_count);
    println!(
        "kdf:            argon2id (m={} KiB, t={}, p={})",
        s.kdf_params.mem_kib, s.kdf_params.t_cost, s.kdf_params.p_cost
    );
    println!(
        "daemon state:   {}",
        match query_daemon_vault_state() {
            DaemonVaultState::NotRunning => "not running".to_string(),
            DaemonVaultState::Known { locked } =>
                if locked { "locked" } else { "unlocked" }.to_string(),
            DaemonVaultState::Unknown(reason) => format!("unknown ({reason})"),
        }
    );
    Ok(())
}

pub(crate) fn query_daemon_vault_state() -> DaemonVaultState {
    let Some(sock) = daemon::socket_path() else {
        return DaemonVaultState::NotRunning;
    };

    let mut stream = match UnixStream::connect(&sock) {
        Ok(s) => s,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            return DaemonVaultState::NotRunning;
        }
        Err(e) => return DaemonVaultState::Unknown(e.to_string()),
    };

    if let Err(e) = stream.set_read_timeout(Some(READ_TIMEOUT)) {
        return DaemonVaultState::Unknown(e.to_string());
    }

    match query_daemon_vault_status(&mut stream) {
        Ok(locked) => DaemonVaultState::Known { locked },
        Err(e) => DaemonVaultState::Unknown(e.to_string()),
    }
}

fn query_daemon_vault_status(stream: &mut UnixStream) -> Result<bool> {
    let handshake_id = uuid::Uuid::new_v4().to_string();
    let req = json!({
        "id": handshake_id,
        "method": "cli.handshake",
        "params": {},
    });
    write_frame(stream, &req)?;
    let resp = read_frame(stream)?;
    if let Some(err) = resp.get("error") {
        anyhow::bail!("handshake refused: {}", err);
    }
    let token = resp
        .get("result")
        .and_then(|r| r.get("session_token"))
        .and_then(|t| t.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing session_token in handshake response"))?
        .to_string();

    let status_id = uuid::Uuid::new_v4().to_string();
    let req = json!({
        "id": status_id,
        "method": "vault.status",
        "params": {},
        "session_token": token,
    });
    write_frame(stream, &req)?;
    let resp = read_frame(stream)?;
    if let Some(err) = resp.get("error") {
        anyhow::bail!("vault.status refused: {}", err);
    }
    resp.get("result")
        .and_then(|r| r.get("locked"))
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow::anyhow!("missing locked field in vault.status response"))
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
