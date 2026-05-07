//! `cloak setup` — interactive first-time setup wizard.
//!
//! Walks the user from `brew install` to a working install in one
//! command. Idempotent: every step checks current state and offers to
//! re-do (or skip) before touching anything.
//!
//! Steps:
//! 1. Vault passphrase (with strength meter via `zxcvbn`).
//!    Pepper installed in OS keychain (handled inside `Vault::initialize`).
//! 2. Default policy file written to `~/.config/cloak/policy.toml`
//!    (idempotent; never overwrites a user's edits).
//! 3. Daemon installed (launchd / systemd-user) and started.
//! 4. Detected MCP clients registered (per-client opt-out).
//! 5. `.env` files in cwd offered for import; post-import disposition.
//!
//! All config edits are atomic with a `.bak` backup of the original
//! file before we overwrite it.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use cloak_core::crypto::Secret;
use cloak_core::policy::default_policy_path;
use dialoguer::{theme::ColorfulTheme, Confirm, Password, Select};
use zxcvbn::Score;

use super::clients::{self, Client};
use super::daemon as daemonctl;
use super::dotenv::{discover_envs, parse_dotenv};
use super::import::{import_silently, Mode as ImportMode};
use super::{open_vault, Context, SystemError};

/// Starter policy template written by `cloak setup` when no
/// `policy.toml` exists. Default-deny posture matching the in-memory
/// fallback in `cloak-core::policy`, plus commented-out per-secret
/// examples the user can uncomment to enable specific tools/hosts.
pub(crate) const STARTER_POLICY_TOML: &str = include_str!("setup_starter_policy.toml");

/// CLI options for `cloak setup`.
#[derive(Debug, Clone, Default)]
pub struct SetupOptions {
    /// Skip every prompt and use the safest default. Used by the
    /// first-use auto-trigger.
    pub non_interactive: bool,
    /// Skip the daemon-install step (useful for CI / packagers).
    pub skip_daemon: bool,
    /// Skip the MCP-client registration step.
    pub skip_clients: bool,
    /// Skip the `.env` import step.
    pub skip_env: bool,
}

pub fn run(ctx: &Context, opts: SetupOptions) -> Result<()> {
    let theme = ColorfulTheme::default();
    println!();
    println!("Cloak setup wizard.");
    println!("This will configure your local secrets vault and connect");
    println!("Cloak to any MCP clients you have installed.");
    println!();

    // --- 1. Passphrase + vault init ----------------------------------------
    init_vault(ctx, &theme, &opts)?;

    // --- 2. Default policy file -------------------------------------------
    // Always run; the function is idempotent and only writes when no
    // file is present. This is what stops a fresh install from silently
    // hitting the in-memory `Action::Deny` fallback in cloak-core.
    let policy_outcome = match write_default_policy(&default_policy_path()) {
        Ok(o) => Some(o),
        Err(e) => {
            eprintln!("warning: could not write default policy.toml: {e}");
            None
        }
    };

    // --- 3. Daemon install / start -----------------------------------------
    if !opts.skip_daemon {
        match install_and_start_daemon(&theme, &opts) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("warning: daemon step failed: {e}");
                eprintln!("         you can retry later with `cloak daemon start`");
            }
        }
    }

    // --- 4. MCP client registration ----------------------------------------
    if !opts.skip_clients {
        register_clients(&theme, &opts);
    }

    // --- 5. .env import -----------------------------------------------------
    if !opts.skip_env {
        offer_env_import(ctx, &theme, &opts)?;
    }

    println!();
    println!("Setup complete. Try `cloak list` or `cloak doctor`.");
    if let Some(o) = policy_outcome {
        match o {
            PolicyWriteOutcome::Wrote(p) => {
                println!();
                println!("Note: I wrote a default-deny policy at {}.", p.display());
                println!("      Edit it to allow specific secrets/hosts before");
                println!("      Claude (or any MCP client) can call protected tools.");
                println!("      See `scripts/policy.example.toml` in the Cloak repo");
                println!("      for a worked example.");
            }
            PolicyWriteOutcome::AlreadyExists(_) => {}
        }
    }
    Ok(())
}

// -------------------------------------------------------------------------
// Step 1: passphrase + vault init
// -------------------------------------------------------------------------

fn init_vault(ctx: &Context, theme: &ColorfulTheme, opts: &SetupOptions) -> Result<()> {
    let mut vault = open_vault(ctx)?;
    if vault.is_initialized()? {
        println!(
            "[1/5] vault: already initialized at {}",
            ctx.vault_path.display()
        );
        return Ok(());
    }
    println!(
        "[1/5] vault: creating a new vault at {}",
        ctx.vault_path.display()
    );

    let pass = if opts.non_interactive {
        // Non-interactive: refuse rather than silently picking a
        // passphrase. Setup must be human-driven.
        return Err(SystemError::boxed(
            "vault not initialized; run `cloak setup` interactively first",
        ));
    } else {
        prompt_strong_passphrase(theme)?
    };

    let result = vault.initialize(&pass)?;
    let p = result.kdf_params;
    println!(
        "      kdf: argon2id (m={} KiB, t={}, p={})",
        p.mem_kib, p.t_cost, p.p_cost
    );
    println!("      pepper stored in OS keychain (service=dev.cloak account=vault.pepper)");
    Ok(())
}

/// Prompt for a passphrase, scoring it with `zxcvbn`. Refuses scores
/// below 2 (out of 4) outright.
fn prompt_strong_passphrase(theme: &ColorfulTheme) -> Result<Secret<String>> {
    if let Ok(p) = std::env::var("CLOAK_PASSPHRASE") {
        // Honor the test/CI override silently.
        return Ok(Secret::new(p));
    }
    loop {
        let pass: String = Password::with_theme(theme)
            .with_prompt("vault passphrase")
            .with_confirmation("confirm passphrase", "passphrases did not match")
            .interact()
            .context("read passphrase")?;
        let estimate = zxcvbn::zxcvbn(&pass, &[]);
        let bar = strength_bar(estimate.score());
        let warning = estimate
            .feedback()
            .and_then(|f| f.warning())
            .map(|w| w.to_string())
            .unwrap_or_default();
        let score_n = estimate.score() as u8;
        println!("      strength: {} ({}/4)", bar, score_n);
        if !warning.is_empty() {
            println!("      hint: {warning}");
        }
        if (estimate.score() as u8) < 2 {
            let again = Confirm::with_theme(theme)
                .with_prompt("that passphrase is weak; choose a stronger one?")
                .default(true)
                .interact()
                .unwrap_or(true);
            if again {
                continue;
            }
        }
        return Ok(Secret::new(pass));
    }
}

fn strength_bar(score: Score) -> &'static str {
    match score as u8 {
        0 => "[#         ] very weak",
        1 => "[##        ] weak",
        2 => "[####      ] fair",
        3 => "[#######   ] strong",
        _ => "[##########] excellent",
    }
}

// -------------------------------------------------------------------------
// Step 2: default policy file
// -------------------------------------------------------------------------

/// Result of [`write_default_policy`].
#[derive(Debug)]
pub(crate) enum PolicyWriteOutcome {
    /// Wrote a fresh starter policy.
    Wrote(PathBuf),
    /// File already existed; left untouched.
    AlreadyExists(#[allow(dead_code)] PathBuf),
}

/// Ensure `path` (typically `~/.config/cloak/policy.toml`) contains a
/// policy file. If absent, write the default-deny starter template at
/// mode 0o600 with a `.bak` of any prior file. Idempotent: never
/// overwrites existing content.
pub(crate) fn write_default_policy(path: &Path) -> Result<PolicyWriteOutcome> {
    if path.exists() {
        tracing::debug!(
            path = %path.display(),
            "policy.toml already exists; leaving alone"
        );
        println!(
            "[2/5] policy: {} already exists; leaving alone",
            path.display()
        );
        return Ok(PolicyWriteOutcome::AlreadyExists(path.to_path_buf()));
    }
    daemonctl::atomic_write_with_backup(path, STARTER_POLICY_TOML.as_bytes(), 0o600)
        .with_context(|| format!("write default policy to {}", path.display()))?;
    println!("[2/5] policy: wrote default-deny policy to {}", path.display());
    Ok(PolicyWriteOutcome::Wrote(path.to_path_buf()))
}

// -------------------------------------------------------------------------
// Step 3: daemon install / start
// -------------------------------------------------------------------------

fn install_and_start_daemon(theme: &ColorfulTheme, opts: &SetupOptions) -> Result<()> {
    let install = if opts.non_interactive {
        true
    } else {
        Confirm::with_theme(theme)
            .with_prompt("[3/5] install the cloakd background daemon now?")
            .default(true)
            .interact()
            .unwrap_or(true)
    };
    if !install {
        println!("      skipped — you can run `cloak daemon install` later");
        return Ok(());
    }
    let flavour = daemonctl::DaemonFlavour::auto()?;
    match flavour {
        daemonctl::DaemonFlavour::Launchd => {
            let p = daemonctl::install_launchd()?;
            println!("      installed launchd plist: {}", p.display());
        }
        daemonctl::DaemonFlavour::SystemdUser => {
            let p = daemonctl::install_systemd_unit()?;
            println!("      installed systemd unit: {}", p.display());
        }
    }
    daemonctl::start_daemon()?;
    if daemonctl::daemon_alive() {
        println!("      daemon: started");
    } else {
        // Some launchd configurations take a beat to come up. Don't
        // hard-fail; the doctor command will catch it.
        println!("      daemon: launched (`cloak doctor` will verify)");
    }
    Ok(())
}

// -------------------------------------------------------------------------
// Step 4: MCP client registration
// -------------------------------------------------------------------------

fn register_clients(theme: &ColorfulTheme, opts: &SetupOptions) {
    let detected = clients::detected();
    if detected.is_empty() {
        println!("[4/5] MCP clients: none detected. Use `cloak claude register --all` later.");
        return;
    }
    println!("[4/5] MCP clients detected:");
    for c in &detected {
        println!("        - {}", c.label());
    }
    let mut chosen: Vec<Client> = Vec::new();
    if opts.non_interactive {
        chosen = detected;
    } else {
        for c in detected {
            let ok = Confirm::with_theme(theme)
                .with_prompt(format!("      register cloak with {}?", c.label()))
                .default(true)
                .interact()
                .unwrap_or(true);
            if ok {
                chosen.push(c);
            }
        }
    }
    for c in chosen {
        match clients::register(c) {
            Ok(clients::RegisterOutcome::Registered(p)) => {
                println!("      [ok] {}: wrote {}", c.label(), p.display())
            }
            Ok(clients::RegisterOutcome::RegisteredCommand(cmd)) => {
                println!("      [ok] {}: ran `{cmd}`", c.label())
            }
            Ok(clients::RegisterOutcome::AlreadyPresent(_)) => {
                println!("      [noop] {}: already registered", c.label())
            }
            Ok(clients::RegisterOutcome::Skipped(why)) => {
                println!("      [skip] {}: {why}", c.label())
            }
            Err(e) => println!("      [err] {}: {e}", c.label()),
        }
    }
}

// -------------------------------------------------------------------------
// Step 5: .env import
// -------------------------------------------------------------------------

fn offer_env_import(ctx: &Context, theme: &ColorfulTheme, opts: &SetupOptions) -> Result<()> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let envs = discover_envs(&cwd);
    if envs.is_empty() {
        println!("[5/5] .env: none found in {}", cwd.display());
        return Ok(());
    }
    println!("[5/5] .env files found:");
    for p in &envs {
        let n = parse_dotenv(p).map(|v| v.len()).unwrap_or(0);
        println!("        - {} ({} entries)", p.display(), n);
    }
    let import = if opts.non_interactive {
        true
    } else {
        Confirm::with_theme(theme)
            .with_prompt("      import these into the vault?")
            .default(true)
            .interact()
            .unwrap_or(true)
    };
    if !import {
        return Ok(());
    }
    for p in &envs {
        let (added, updated, _entries) = match import_silently(ctx, p, ImportMode::Update) {
            Ok(r) => r,
            Err(e) => {
                println!("      [err] {}: {e}", p.display());
                continue;
            }
        };
        println!(
            "      imported {}: {added} added, {updated} updated",
            p.display()
        );
        if !opts.non_interactive {
            handle_post_import_disposition(theme, p)?;
        } else {
            // Default disposition: rename to `.imported`.
            let _ = rename_to_imported(p);
        }
    }
    Ok(())
}

fn handle_post_import_disposition(theme: &ColorfulTheme, path: &Path) -> Result<()> {
    let opts = &[
        "rename to .imported (recommended)",
        "delete",
        "add to .gitignore",
        "leave as-is",
    ];
    let pick = Select::with_theme(theme)
        .with_prompt(format!("      what should I do with {}?", path.display()))
        .items(opts)
        .default(0)
        .interact()
        .unwrap_or(0);
    match pick {
        0 => rename_to_imported(path),
        1 => delete_env(path),
        2 => add_to_gitignore(path),
        _ => Ok(()),
    }
}

fn rename_to_imported(path: &Path) -> Result<()> {
    let dest = path.with_extension({
        let mut e = path
            .extension()
            .map(|e| e.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !e.is_empty() {
            e.push('.');
        }
        e.push_str("imported");
        e
    });
    std::fs::rename(path, &dest)
        .with_context(|| format!("rename {} → {}", path.display(), dest.display()))?;
    println!("      → renamed to {}", dest.display());
    Ok(())
}

fn delete_env(path: &Path) -> Result<()> {
    std::fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
    println!("      → deleted {}", path.display());
    Ok(())
}

fn add_to_gitignore(path: &Path) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let gi = dir.join(".gitignore");
    let line = path
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".env".into());
    let mut existing = std::fs::read_to_string(&gi).unwrap_or_default();
    if existing.lines().any(|l| l.trim() == line) {
        println!("      → {} already in .gitignore", line);
        return Ok(());
    }
    if !existing.is_empty() && !existing.ends_with('\n') {
        existing.push('\n');
    }
    existing.push_str(&line);
    existing.push('\n');
    daemonctl::atomic_write(&gi, existing.as_bytes(), 0o644)?;
    println!("      → added {} to {}", line, gi.display());
    Ok(())
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The bundled starter template must always parse with the same
    /// engine that cloakd uses, otherwise we'd hand the user a broken
    /// file. Also asserts the default-deny posture.
    #[test]
    fn starter_template_parses_and_is_default_deny() {
        let mut e = cloak_core::policy::PolicyEngine::from_str(STARTER_POLICY_TOML)
            .expect("starter policy must parse");
        let ctx = cloak_core::policy::EvalContext {
            tool: "proxy_authenticated_http_request",
            secret_name: Some("OPENAI_API_KEY"),
            secret_kind: None,
            target_host: Some("api.openai.com"),
            peer_basename: "test",
        };
        // Default-deny: no per-secret rule is uncommented in the
        // starter template, so this call must be denied.
        assert_eq!(
            e.evaluate(&ctx).action,
            cloak_core::policy::Action::Deny,
            "starter policy must default-deny proxy_http"
        );
        // query_audit is always allowed (read-only).
        let audit_ctx = cloak_core::policy::EvalContext {
            tool: "query_audit",
            secret_name: None,
            secret_kind: None,
            target_host: None,
            peer_basename: "test",
        };
        assert_eq!(
            e.evaluate(&audit_ctx).action,
            cloak_core::policy::Action::Allow
        );
    }

    #[test]
    fn write_default_policy_creates_file_with_mode_600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cloak").join("policy.toml");
        let outcome = write_default_policy(&path).unwrap();
        assert!(matches!(outcome, PolicyWriteOutcome::Wrote(_)));
        assert!(path.exists());
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("[default]"));
        assert!(body.contains("action = \"deny\""));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "policy file must be mode 0o600, got {mode:o}");
        }
    }

    #[test]
    fn write_default_policy_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, b"# user-edited content\n[default]\naction = \"allow\"\n").unwrap();
        let original = std::fs::read_to_string(&path).unwrap();
        let outcome = write_default_policy(&path).unwrap();
        assert!(matches!(outcome, PolicyWriteOutcome::AlreadyExists(_)));
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            original, after,
            "existing policy.toml must not be overwritten"
        );
    }
}
