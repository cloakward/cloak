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
/// warning but never block the command (we'd rather complete the user's
/// action than fail it because the audit dir is read-only).
pub fn append(tool: &str, secret: Option<&str>, result: AuditResult, note: Option<String>) {
    let path = match default_audit_path() {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "audit: skip (no path)");
            return;
        }
    };
    let mut log = match AuditLog::open(&path) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = %e, "audit: open failed");
            return;
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
    if let Err(e) = log.append(draft) {
        tracing::warn!(error = %e, "audit: append failed");
    }
}
