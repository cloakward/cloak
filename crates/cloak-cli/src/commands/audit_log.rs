//! Thin CLI-side wrapper around [`cloak_core::audit::AuditLog`] so
//! `cloak {run, export, panic}` can record their actions without going
//! through an IPC method we don't have. We open the same audit file the
//! daemon uses (`<data_dir>/cloak/audit.jsonl`), append a single entry,
//! and close — all under the per-process `flock` the audit module
//! provides for multi-writer safety.
//!
//! Audit entries **never** carry the secret value. They carry the secret
//! *name*, the calling process pid, and a short tool tag (e.g.
//! `cli.run`).

use std::path::PathBuf;

use anyhow::Result;
use cloak_core::audit::{AuditDraft, AuditLog, AuditResult, PeerSummary};

/// Default audit log path: `<data_dir>/cloak/audit.jsonl`.
pub fn default_audit_path() -> Result<PathBuf> {
    let base = dirs::data_dir().ok_or_else(|| anyhow::anyhow!("no data dir"))?;
    Ok(base.join("cloak").join("audit.jsonl"))
}

/// Build a [`PeerSummary`] for the running CLI process.
pub fn cli_peer() -> PeerSummary {
    let pid = std::process::id() as i32;
    let basename = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|f| f.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "cloak".to_string());
    PeerSummary {
        pid,
        basename,
        code_sig_hex: None,
    }
}

/// Append an entry. Best-effort: failures are surfaced as a tracing
/// warning but never block metadata-only commands.
pub fn append(tool: &str, secret: Option<&str>, result: AuditResult, note: Option<String>) {
    if let Err(e) = append_required(tool, secret, result, note) {
        tracing::warn!(error = %e, "audit: append failed");
    }
}

/// Append an entry and fail if it cannot be persisted. Plaintext-bearing and
/// state-mutating operations use this before the risky side effect so audit
/// logging is fail-closed for those paths.
pub fn append_required(
    tool: &str,
    secret: Option<&str>,
    result: AuditResult,
    note: Option<String>,
) -> Result<()> {
    let path = match default_audit_path() {
        Ok(p) => p,
        Err(e) => {
            anyhow::bail!("audit path unavailable: {e}");
        }
    };
    let mut log = match AuditLog::open(&path) {
        Ok(l) => l,
        Err(e) => {
            anyhow::bail!("audit open failed: {e}");
        }
    };
    let draft = AuditDraft {
        peer: cli_peer(),
        tool: tool.to_string(),
        secret: secret.map(str::to_string),
        target: None,
        result,
        note,
    };
    log.append(draft)?;
    Ok(())
}

pub fn run_verify() -> Result<()> {
    let path = default_audit_path()?;
    let log = AuditLog::open(&path)?;
    let count = log.verify()?;
    println!("audit log ok: {count} entries");
    println!("path: {}", path.display());
    Ok(())
}

pub fn run_adopt_head(yes: bool) -> Result<()> {
    if !yes {
        anyhow::bail!(
            "refusing to adopt audit head without --yes; review the existing audit log first"
        );
    }
    let path = default_audit_path()?;
    let head = AuditLog::adopt_existing_head(&path)?;
    println!("audit head anchor adopted: {} entries", head.seq);
    println!("path: {}", path.display());
    Ok(())
}
