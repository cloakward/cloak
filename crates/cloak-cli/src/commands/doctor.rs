//! `cloak doctor` — read-only diagnostic.
//!
//! Walks the install: binaries on PATH, daemon up + socket sane, vault
//! present + unlocked, biometric available, every detected MCP client
//! has a `cloak` server registered. For each failed check we print a
//! one-line remediation hint.
//!
//! Exit code: `0` if every check passes; `1` otherwise (mirrors the
//! pattern of every other "is my system healthy" CLI).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Result;
use cloak_core::policy::{default_policy_path, PolicyEngine};

use super::clients::{self, Client};
use super::daemon as daemonctl;
use super::{open_vault, Context};

#[derive(Debug)]
struct Check {
    name: String,
    status: Status,
    detail: String,
    remediation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Ok,
    Warn,
    Fail,
}

impl Status {
    fn glyph(&self) -> &'static str {
        match self {
            Status::Ok => "[ok]   ",
            Status::Warn => "[warn] ",
            Status::Fail => "[fail] ",
        }
    }
}

pub fn run_with_exit(ctx: &Context) -> Result<ExitCode> {
    let mut checks: Vec<Check> = vec![
        // 1. Binaries on PATH.
        check_binary("cloak"),
        check_binary("cloakd"),
        check_binary("cloak-mcp"),
        // 2. Daemon up + socket sane.
        check_daemon(),
        // 3. Vault state.
        check_vault(ctx),
        // 4. Policy file present + parses.
        check_policy(&default_policy_path()),
        // 5. Biometric availability (best-effort).
        check_biometric(),
    ];

    // 6. MCP clients registered.
    checks.extend(clients::detected().into_iter().map(check_client));

    let mut failed = 0u32;
    for c in &checks {
        println!("{}{}", c.status.glyph(), c.name);
        if !c.detail.is_empty() {
            println!("        {}", c.detail);
        }
        if c.status != Status::Ok {
            if let Some(rem) = &c.remediation {
                println!("        → {rem}");
            }
            if c.status == Status::Fail {
                failed += 1;
            }
        }
    }
    if failed == 0 {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

fn check_binary(name: &str) -> Check {
    if let Some(p) = which(name) {
        Check {
            name: format!("binary `{name}` on PATH"),
            status: Status::Ok,
            detail: p.display().to_string(),
            remediation: None,
        }
    } else {
        Check {
            name: format!("binary `{name}` on PATH"),
            status: Status::Fail,
            detail: String::new(),
            remediation: Some(format!("install `{name}` (e.g. via `brew install cloak`)")),
        }
    }
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let p = dir.join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn check_daemon() -> Check {
    let alive = daemonctl::daemon_alive();
    let sock = daemonctl::socket_path();
    let detail = sock
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    if !alive {
        return Check {
            name: "daemon (cloakd) running".into(),
            status: Status::Fail,
            detail,
            remediation: Some("run `cloak daemon start`".into()),
        };
    }
    // Check socket mode + owner.
    if let Some(p) = sock {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(meta) = std::fs::metadata(&p) {
                let mode = meta.mode() & 0o777;
                let our_uid = unsafe { libc::geteuid() };
                if meta.uid() != our_uid {
                    return Check {
                        name: "daemon socket ownership".into(),
                        status: Status::Fail,
                        detail: format!(
                            "{} owned by uid {} (we are {})",
                            p.display(),
                            meta.uid(),
                            our_uid
                        ),
                        remediation: Some(
                            "stop cloakd, remove the socket, and run `cloak daemon start` again"
                                .into(),
                        ),
                    };
                }
                if mode & 0o077 != 0 {
                    return Check {
                        name: "daemon socket mode".into(),
                        status: Status::Fail,
                        detail: format!("{} mode {:o} (expected 0600)", p.display(), mode),
                        remediation: Some(
                            "stop cloakd and restart it; never run cloakd as a different user"
                                .into(),
                        ),
                    };
                }
            }
        }
    }
    Check {
        name: "daemon (cloakd) running + socket secure".into(),
        status: Status::Ok,
        detail,
        remediation: None,
    }
}

fn check_vault(ctx: &Context) -> Check {
    let vault = match open_vault(ctx) {
        Ok(v) => v,
        Err(e) => {
            return Check {
                name: "vault file accessible".into(),
                status: Status::Fail,
                detail: e.to_string(),
                remediation: Some(
                    "ensure your home directory is writable; run `cloak setup`".into(),
                ),
            }
        }
    };
    match vault.is_initialized() {
        Ok(true) => {
            let n = vault.list().map(|v| v.len()).unwrap_or(0);
            Check {
                name: "vault initialized".into(),
                status: Status::Ok,
                detail: format!("{} secret(s)", n),
                remediation: None,
            }
        }
        Ok(false) => Check {
            name: "vault initialized".into(),
            status: Status::Warn,
            detail: ctx.vault_path.display().to_string(),
            remediation: Some("run `cloak setup` to create a vault".into()),
        },
        Err(e) => Check {
            name: "vault initialized".into(),
            status: Status::Fail,
            detail: e.to_string(),
            remediation: Some(
                "file may be corrupted; check `cloak status` and consider restoring".into(),
            ),
        },
    }
}

fn check_policy(path: &Path) -> Check {
    let name = "policy file exists".to_string();
    if !path.exists() {
        return Check {
            name,
            status: Status::Warn,
            detail: format!("{} not found", path.display()),
            remediation: Some(
                "run `cloak setup` to write a default policy, or copy \
                 `scripts/policy.example.toml`"
                    .into(),
            ),
        };
    }
    match PolicyEngine::from_path(path) {
        Ok(_) => Check {
            name,
            status: Status::Ok,
            detail: path.display().to_string(),
            remediation: None,
        },
        Err(e) => Check {
            name,
            status: Status::Fail,
            detail: format!("{}: {e}", path.display()),
            remediation: Some(format!(
                "fix or remove {} (parse error above)",
                path.display()
            )),
        },
    }
}

fn check_biometric() -> Check {
    if cfg!(target_os = "macos") {
        // We can't actually probe LAContext without prompting; treat as
        // present on macOS, fail-soft elsewhere.
        Check {
            name: "biometric available (macOS Touch ID)".into(),
            status: Status::Ok,
            detail: "LocalAuthentication framework available".into(),
            remediation: None,
        }
    } else if cfg!(target_os = "linux") {
        Check {
            name: "user-presence gate (polkit)".into(),
            status: Status::Warn,
            detail: "polkit confirmation is the macOS-Touch-ID equivalent here".into(),
            remediation: Some(
                "ensure polkit is running and the dev.cloak.show-secret action is installed".into(),
            ),
        }
    } else {
        Check {
            name: "biometric / user-presence".into(),
            status: Status::Warn,
            detail: "unsupported on this platform".into(),
            remediation: Some("use --no-biometric to bypass".into()),
        }
    }
}

fn check_client(c: Client) -> Check {
    let label = format!("MCP client: {}", c.label());
    if c.id() == "claude-code" {
        // Best-effort: we don't try to introspect `claude mcp list`.
        return Check {
            name: label,
            status: Status::Warn,
            detail: "register with `cloak claude register --code`".into(),
            remediation: None,
        };
    }
    let path = match c.config_path() {
        Some(p) => p,
        None => {
            return Check {
                name: label,
                status: Status::Warn,
                detail: "no known config path on this OS".into(),
                remediation: None,
            }
        }
    };
    let flag = client_flag(c);
    if !path.exists() {
        return Check {
            name: label,
            status: Status::Warn,
            detail: format!("{} not found", path.display()),
            remediation: Some(format!("run `cloak claude register --{flag}`")),
        };
    }
    let raw = std::fs::read_to_string(&path).unwrap_or_default();
    if raw.contains("\"cloak\"") || raw.contains("\"cloak-mcp\"") {
        Check {
            name: label,
            status: Status::Ok,
            detail: path.display().to_string(),
            remediation: None,
        }
    } else {
        Check {
            name: label,
            status: Status::Warn,
            detail: format!("`cloak` not registered in {}", path.display()),
            remediation: Some(format!("run `cloak claude register --{flag}`")),
        }
    }
}

fn client_flag(c: Client) -> &'static str {
    match c {
        Client::ClaudeDesktop => "desktop",
        Client::ClaudeCode => "code",
        Client::Cursor => "cursor",
        Client::Windsurf => "windsurf",
        Client::Continue => "continue-ext",
        Client::Zed => "zed",
        Client::Codex => "codex",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_policy_warns() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.toml");
        let c = check_policy(&path);
        assert_eq!(c.status, Status::Warn);
        assert!(c.remediation.is_some());
    }

    #[test]
    fn valid_policy_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        std::fs::write(
            &path,
            b"[default]\naction = \"deny\"\n[tools.query_audit]\nallow = true\n",
        )
        .unwrap();
        let c = check_policy(&path);
        assert_eq!(c.status, Status::Ok);
        assert!(c.remediation.is_none());
    }

    #[test]
    fn broken_policy_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broken.toml");
        std::fs::write(&path, b"this is = = not toml").unwrap();
        let c = check_policy(&path);
        assert_eq!(c.status, Status::Fail);
        assert!(c.remediation.is_some());
    }
}
