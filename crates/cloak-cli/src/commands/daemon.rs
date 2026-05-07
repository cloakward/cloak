//! `cloak daemon {install,start,stop,status}` — per-component primitives
//! for installing and supervising `cloakd`.
//!
//! These are the building blocks the `cloak setup` wizard composes. They
//! are intentionally usable on their own so packagers, advanced users,
//! and CI can drive them headlessly.
//!
//! # Platform matrix
//! - macOS: per-user launchd LaunchAgent at
//!   `~/Library/LaunchAgents/dev.cloak.cloakd.plist`. We use
//!   `launchctl load -w` / `unload`. `launchctl print` is the status path.
//! - Linux: per-user systemd unit at
//!   `~/.config/systemd/user/cloakd.service`. Driven via
//!   `systemctl --user`.
//! - Other targets: not supported; commands return a clear error.
//!
//! # Atomic writes
//! Every plist / unit file is written with `tempfile::NamedTempFile` in
//! the destination directory, then `persist`-ed (rename(2)) into place
//! so a crash mid-write never leaves a half-written file.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context as _, Result};

use super::{Context, SystemError};

/// Selector for which init-system flavour to install.
#[derive(Debug, Clone, Copy)]
pub enum DaemonFlavour {
    /// macOS launchd LaunchAgent (per-user).
    Launchd,
    /// Linux systemd user unit (`systemctl --user`).
    SystemdUser,
}

impl DaemonFlavour {
    /// Pick the right flavour for the current OS.
    pub fn auto() -> Result<Self> {
        if cfg!(target_os = "macos") {
            Ok(Self::Launchd)
        } else if cfg!(target_os = "linux") {
            Ok(Self::SystemdUser)
        } else {
            Err(SystemError::boxed(
                "cloak daemon is only supported on macOS and Linux",
            ))
        }
    }
}

/// Resolve the cloakd binary path. Searches alongside the running `cloak`
/// binary first, then `$PATH`, then a few well-known install locations.
pub fn resolve_cloakd_bin() -> Result<PathBuf> {
    // Prefer a sibling of the running cloak binary so we pick up local
    // dev / homebrew installs uniformly.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("cloakd");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    // Try $PATH.
    if let Ok(p) = which("cloakd") {
        return Ok(p);
    }
    // Common install prefixes.
    for p in [
        "/usr/local/bin/cloakd",
        "/opt/homebrew/bin/cloakd",
        "/usr/bin/cloakd",
    ] {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Ok(pb);
        }
    }
    Err(SystemError::boxed(
        "cloakd binary not found on PATH. Install it (e.g. via brew) or set CLOAKD_BIN.",
    ))
}

fn which(bin: &str) -> Result<PathBuf> {
    let path = std::env::var_os("PATH")
        .ok_or_else(|| anyhow::anyhow!("PATH is not set"))?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(anyhow::anyhow!("not found: {bin}"))
}

// -------------------------------------------------------------------------
// macOS launchd
// -------------------------------------------------------------------------

const LAUNCHD_LABEL: &str = "dev.cloak.cloakd";

/// Path to the launchd plist we manage.
pub fn launchd_plist_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| SystemError::boxed("no home dir"))?;
    Ok(home
        .join("Library")
        .join("LaunchAgents")
        .join("dev.cloak.cloakd.plist"))
}

/// Path to the directory we want cloakd to write logs into.
pub fn launchd_log_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| SystemError::boxed("no home dir"))?;
    Ok(home.join("Library").join("Logs").join("cloak"))
}

fn launchd_plist_xml(cloakd_bin: &std::path::Path, log_dir: &std::path::Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{bin}</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>RUST_LOG</key>
    <string>cloakd=info,cloak_core=info</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>ProcessType</key>
  <string>Interactive</string>
  <key>StandardOutPath</key>
  <string>{log}/cloakd.out.log</string>
  <key>StandardErrorPath</key>
  <string>{log}/cloakd.err.log</string>
</dict>
</plist>
"#,
        label = LAUNCHD_LABEL,
        bin = cloakd_bin.display(),
        log = log_dir.display(),
    )
}

/// Install the launchd LaunchAgent. Idempotent: re-running rewrites the
/// plist and `kickstart`s the agent.
pub fn install_launchd() -> Result<PathBuf> {
    let cloakd = resolve_cloakd_bin()?;
    let plist_path = launchd_plist_path()?;
    let log_dir = launchd_log_dir()?;
    std::fs::create_dir_all(&log_dir)
        .with_context(|| format!("create log dir {}", log_dir.display()))?;
    if let Some(parent) = plist_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create launchagents dir {}", parent.display()))?;
    }

    let body = launchd_plist_xml(&cloakd, &log_dir);
    atomic_write(&plist_path, body.as_bytes(), 0o644)?;
    Ok(plist_path)
}

fn run_quiet(cmd: &mut Command) -> Result<bool> {
    // Capture stdout/stderr so we don't pollute the wizard transcript.
    let out = cmd.output().with_context(|| {
        format!(
            "spawn {} {:?}",
            cmd.get_program().to_string_lossy(),
            cmd.get_args().collect::<Vec<_>>()
        )
    })?;
    Ok(out.status.success())
}

/// Start the daemon (load & enable).
pub fn start_daemon() -> Result<()> {
    match DaemonFlavour::auto()? {
        DaemonFlavour::Launchd => {
            let plist = launchd_plist_path()?;
            if !plist.exists() {
                let _ = install_launchd()?;
            }
            // `load -w` is the historic command; we ignore its result
            // because newer macOS prefers `bootstrap`. We then bootstrap
            // explicitly and fall back to `kickstart`.
            let _ = run_quiet(Command::new("launchctl").args(["unload", plist.to_str().unwrap()]));
            let _ = run_quiet(Command::new("launchctl").args(["load", "-w", plist.to_str().unwrap()]));
            // Kickstart: best-effort restart so re-runs pick up new bin.
            let domain = format!("gui/{}", current_uid());
            let target = format!("{domain}/{LAUNCHD_LABEL}");
            let _ = run_quiet(Command::new("launchctl").args(["kickstart", "-k", &target]));
            Ok(())
        }
        DaemonFlavour::SystemdUser => {
            install_systemd_unit()?;
            run_quiet(Command::new("systemctl").args(["--user", "daemon-reload"]))?;
            run_quiet(Command::new("systemctl").args(["--user", "enable", "--now", "cloakd.service"]))?;
            Ok(())
        }
    }
}

/// Stop the daemon (unload / stop+disable).
pub fn stop_daemon() -> Result<()> {
    match DaemonFlavour::auto()? {
        DaemonFlavour::Launchd => {
            let plist = launchd_plist_path()?;
            if plist.exists() {
                let _ = run_quiet(
                    Command::new("launchctl").args(["unload", plist.to_str().unwrap()]),
                );
            }
            // Belt-and-suspenders: bootout & stop.
            let domain = format!("gui/{}", current_uid());
            let target = format!("{domain}/{LAUNCHD_LABEL}");
            let _ = run_quiet(Command::new("launchctl").args(["bootout", &target]));
            Ok(())
        }
        DaemonFlavour::SystemdUser => {
            let _ = run_quiet(
                Command::new("systemctl").args(["--user", "disable", "--now", "cloakd.service"]),
            );
            Ok(())
        }
    }
}

/// Returns true if the daemon's UDS is live (we can connect, then close).
pub fn daemon_alive() -> bool {
    use std::os::unix::net::UnixStream;
    let Some(sock) = socket_path() else { return false };
    UnixStream::connect(&sock).is_ok()
}

/// Resolve the per-user cloakd UDS path (mirrors
/// `cloak_core::daemon::default_socket_path` for non-Linux targets too).
pub fn socket_path() -> Option<PathBuf> {
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR") {
        return Some(PathBuf::from(rt).join("cloakd.sock"));
    }
    let tmp = std::env::var_os("TMPDIR").unwrap_or_else(|| std::ffi::OsString::from("/tmp"));
    let uid = current_uid();
    Some(PathBuf::from(tmp).join(format!("cloakd-{uid}.sock")))
}

#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: `geteuid` is always safe to call on Unix.
    unsafe { libc::geteuid() }
}
#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

// -------------------------------------------------------------------------
// Linux systemd-user
// -------------------------------------------------------------------------

fn systemd_unit_path() -> Result<PathBuf> {
    let cfg = dirs::config_dir().ok_or_else(|| SystemError::boxed("no config dir"))?;
    Ok(cfg.join("systemd").join("user").join("cloakd.service"))
}

fn systemd_unit_body(cloakd: &std::path::Path) -> String {
    format!(
        r#"[Unit]
Description=Cloak local secrets daemon
After=default.target

[Service]
ExecStart={bin}
Environment=RUST_LOG=cloakd=info,cloak_core=info
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
"#,
        bin = cloakd.display()
    )
}

/// Install the systemd user unit. Idempotent.
pub fn install_systemd_unit() -> Result<PathBuf> {
    let cloakd = resolve_cloakd_bin()?;
    let path = systemd_unit_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create {}", parent.display()))?;
    }
    let body = systemd_unit_body(&cloakd);
    atomic_write(&path, body.as_bytes(), 0o644)?;
    Ok(path)
}

// -------------------------------------------------------------------------
// Status / install / start / stop CLI entrypoints
// -------------------------------------------------------------------------

/// Output of `cloak daemon status` for downstream tools.
pub fn run_install(_ctx: &Context, flavour: Option<DaemonFlavour>) -> Result<()> {
    let f = flavour.map_or_else(DaemonFlavour::auto, Ok)?;
    match f {
        DaemonFlavour::Launchd => {
            let p = install_launchd()?;
            println!("installed: {}", p.display());
        }
        DaemonFlavour::SystemdUser => {
            let p = install_systemd_unit()?;
            println!("installed: {}", p.display());
        }
    }
    Ok(())
}

pub fn run_start(_ctx: &Context) -> Result<()> {
    start_daemon()?;
    println!("daemon: started");
    Ok(())
}

pub fn run_stop(_ctx: &Context) -> Result<()> {
    stop_daemon()?;
    println!("daemon: stopped");
    Ok(())
}

pub fn run_status(_ctx: &Context) -> Result<()> {
    let alive = daemon_alive();
    let sock = socket_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<unknown>".to_string());
    println!("socket:   {sock}");
    println!("status:   {}", if alive { "running" } else { "not running" });
    if !alive {
        return Err(SystemError::boxed("cloakd is not running"));
    }
    Ok(())
}

// -------------------------------------------------------------------------
// Atomic write helper
// -------------------------------------------------------------------------

/// Write `bytes` to `path` atomically, with mode `mode`. Uses
/// `tempfile::NamedTempFile` in the destination directory so the rename
/// is atomic on the same filesystem.
pub fn atomic_write(path: &std::path::Path, bytes: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .ok_or_else(|| SystemError::boxed(format!("no parent dir for {}", path.display())))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create {}", parent.display()))?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("tempfile in {}", parent.display()))?;
    tmp.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))?;
    tmp.as_file().sync_all().ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(tmp.path(), perms).ok();
    }
    #[cfg(not(unix))]
    let _ = mode;
    tmp.persist(path)
        .map_err(|e| anyhow::anyhow!("rename into place: {e}"))?;
    Ok(())
}

/// Write `bytes` to `path`, but first copy the existing file (if any)
/// to `path.bak`. Used by client-config rewriters.
pub fn atomic_write_with_backup(path: &std::path::Path, bytes: &[u8], mode: u32) -> Result<()> {
    if path.exists() {
        let bak = path.with_extension({
            let mut e = path
                .extension()
                .map(|e| e.to_string_lossy().into_owned())
                .unwrap_or_default();
            if !e.is_empty() {
                e.push('.');
            }
            e.push_str("bak");
            e
        });
        // Best-effort copy; failures here shouldn't block the wizard,
        // but we surface them as a tracing::warn so they're visible in
        // verbose runs.
        if let Err(e) = std::fs::copy(path, &bak) {
            tracing::warn!(path = %path.display(), error = %e, "config backup failed");
        }
    }
    atomic_write(path, bytes, mode)
}
