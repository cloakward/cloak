//! Top-level CLI dispatch.
//!
//! This module owns the [`clap`]-derive types ([`Cli`], [`Command`]) and
//! is the single entry point called from `main.rs`. Each subcommand is
//! implemented in its own submodule under `commands/`.
//!
//! # Exit codes
//!
//! - `0` — success.
//! - `1` — user-facing error (wrong passphrase, secret not found,
//!   biometric failed, refusing to write to non-TTY, invalid input).
//! - `2` — system / config error (vault not initialized when expected,
//!   IO failure, malformed flag).

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use cloak_core::vault::{SecretKind, Vault};

mod add;
mod audit_log;
mod backup;
mod clients;
mod completions;
mod daemon;
mod daemon_unlock;
mod doctor;
mod dotenv;
mod export;
mod get;
mod import;
mod init;
mod list;
mod panic;
mod recovery_display;
mod restore;
mod rm;
mod run;
mod set;
mod setup;
mod show;
mod status;
mod unlock;

// -------------------------------------------------------------------------
// CLI types
// -------------------------------------------------------------------------

/// `cloak` — local secrets vault for Claude Desktop and friends.
#[derive(Debug, Parser)]
#[command(
    name = "cloak",
    version,
    about = "Cloak — MCP-native secrets vault.",
    long_about = "Cloak is a local secrets vault. Secrets are AEAD-encrypted at rest under \
                  a key derived from your passphrase via Argon2id. Reveal is gated behind \
                  Touch ID on macOS."
)]
pub struct Cli {
    /// Path to the vault file (default: `$DATA_DIR/cloak/vault.cloak`).
    #[arg(long, global = true, value_name = "PATH")]
    pub vault: Option<PathBuf>,

    /// Disable Touch ID; always fall back to passphrase re-entry on
    /// `cloak show`.
    #[arg(long, global = true)]
    pub no_biometric: bool,

    #[command(subcommand)]
    pub command: Command,
}

/// All top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Interactive first-time setup (vault + daemon + MCP clients + .env).
    Setup {
        /// Skip the daemon-install step.
        #[arg(long)]
        skip_daemon: bool,
        /// Skip the MCP-client registration step.
        #[arg(long)]
        skip_clients: bool,
        /// Skip the `.env` import step.
        #[arg(long)]
        skip_env: bool,
        /// Run setup from a non-TTY context like a Claude Desktop
        /// extension. Routes interactive prompts (passphrase, etc.)
        /// through native OS dialogs (`osascript` on macOS,
        /// `zenity` / `kdialog` on Linux) instead of `dialoguer`,
        /// which would otherwise fail without a controlling TTY.
        #[arg(long = "from-dxt")]
        from_dxt: bool,
    },

    /// Read-only diagnostic. Exits 1 if any check fails.
    Doctor,

    /// Initialize a new vault (interactive passphrase + KDF autotune).
    Init,

    /// Add a new secret. Prompts for the value with echo OFF.
    Add {
        /// User-visible name (must be unique within the vault).
        name: String,
        /// Coarse classification.
        #[arg(long, value_enum, default_value_t = KindArg::ApiKey)]
        kind: KindArg,
        /// Free-form tags. Repeat the flag for multiple.
        #[arg(long = "tag", value_name = "TAG")]
        tags: Vec<String>,
    },

    /// Update the value of an existing secret. Prompts with echo OFF.
    Set {
        /// Name of the secret to update.
        name: String,
    },

    /// Get metadata for a secret (name / kind / tags / timestamps).
    /// Never returns plaintext.
    Get {
        /// Name of the secret to inspect.
        name: String,
    },

    /// List secrets (metadata only). Empty vault prints "(no secrets)".
    List,

    /// Remove secret(s). Bulk modes: `--tag T`, `--all`.
    Rm {
        /// Name of the secret to remove.
        name: Option<String>,
        /// Skip the confirmation prompt.
        #[arg(short = 'y', long = "yes")]
        yes: bool,
        /// Delete every secret with this tag.
        #[arg(long = "tag", value_name = "TAG", conflicts_with = "all")]
        tag: Option<String>,
        /// Delete every secret in the vault. Requires extra confirmation.
        #[arg(long = "all", conflicts_with = "tag")]
        all: bool,
    },

    /// Reveal a secret's plaintext (Touch ID gated, TTY-only).
    Show {
        /// Name of the secret to reveal.
        name: String,
        /// Allow writing the plaintext to a non-TTY (file / pipe).
        #[arg(long)]
        allow_redirect: bool,
        /// Append a trailing newline after the plaintext.
        #[arg(long)]
        newline: bool,
    },

    /// Print vault status (path, record count, KDF params, lock state).
    Status,

    /// Print shell completions.
    Completions {
        /// Target shell.
        shell: clap_complete::Shell,
    },

    /// Push the vault passphrase to the running `cloakd` so MCP peers
    /// can serve requests.
    DaemonUnlock,

    /// Import a `.env` file into the vault.
    Import {
        /// Path to the `.env` file (default: ./.env).
        path: Option<PathBuf>,
        /// Add new + overwrite existing keys.
        #[arg(long, conflicts_with = "replace")]
        update: bool,
        /// `--update` plus delete vault entries not in the file.
        #[arg(long)]
        replace: bool,
    },

    /// Export the vault to a `.env` file (Touch ID gated).
    Export {
        /// Destination path (default: ./.env).
        path: Option<PathBuf>,
        /// Overwrite the destination if it exists.
        #[arg(long)]
        force: bool,
    },

    /// Run a command with vault secrets injected as environment variables.
    Run {
        /// Comma-separated list of secret names to inject (default: all).
        #[arg(long, value_name = "K1,K2", value_delimiter = ',')]
        only: Vec<String>,
        /// The command and its arguments.
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },

    /// Emergency: lock the vault, kill the daemon, print rotation worksheet.
    Panic,

    /// Manage the cloakd background daemon (install/start/stop/status).
    Daemon {
        #[command(subcommand)]
        cmd: DaemonCmd,
    },

    /// Register `cloak` with installed MCP clients (Claude Desktop, etc.).
    Claude {
        #[command(subcommand)]
        cmd: ClaudeCmd,
    },

    /// Re-derive vault access from your 24-word BIP-39 recovery seed.
    Restore,

    /// Backup utilities: confirm the recovery seed you wrote down.
    Backup {
        #[command(subcommand)]
        cmd: BackupCmd,
    },
}

/// `cloak backup ...` subcommands.
#[derive(Debug, Subcommand)]
pub enum BackupCmd {
    /// Surface the recovery seed disposition for this vault. The
    /// 24-word phrase is NOT re-displayed — Cloak does not keep a
    /// copy. This command confirms the wrap exists and is reachable.
    Mnemonic,
    /// Round-trip a candidate 24-word seed against the vault's stored
    /// recovery wrap. Confirms you wrote the words down correctly.
    Verify,
}

/// `cloak daemon ...` subcommands.
#[derive(Debug, Subcommand)]
pub enum DaemonCmd {
    /// Install the daemon's launchd plist or systemd unit.
    Install {
        /// Force the launchd flavour (macOS).
        #[arg(long, conflicts_with = "systemd_user")]
        launchd: bool,
        /// Force the systemd-user flavour (Linux).
        #[arg(long, conflicts_with = "launchd")]
        systemd_user: bool,
    },
    /// Start the daemon (load + enable).
    Start,
    /// Stop the daemon (unload + disable).
    Stop,
    /// Print whether the daemon is running.
    Status,
}

/// `cloak claude ...` (and friends) subcommands.
#[derive(Debug, Subcommand)]
pub enum ClaudeCmd {
    /// Register the `cloak` MCP server with one or more clients.
    Register(ClientFlags),
    /// Remove the `cloak` MCP server entry from one or more clients.
    Unregister(ClientFlags),
}

#[derive(Debug, clap::Args)]
pub struct ClientFlags {
    /// Apply to every supported client.
    #[arg(long)]
    pub all: bool,
    /// Claude Desktop.
    #[arg(long)]
    pub desktop: bool,
    /// Claude Code CLI.
    #[arg(long)]
    pub code: bool,
    /// Cursor.
    #[arg(long)]
    pub cursor: bool,
    /// Windsurf.
    #[arg(long)]
    pub windsurf: bool,
    /// Continue.dev.
    #[arg(long, name = "continue-ext")]
    pub continue_ext: bool,
    /// Zed.
    #[arg(long)]
    pub zed: bool,
    /// Codex.
    #[arg(long)]
    pub codex: bool,
}

impl ClientFlags {
    fn into_selection(self) -> clients::RegisterSelection {
        let mut chosen = Vec::new();
        if self.desktop {
            chosen.push(clients::Client::ClaudeDesktop);
        }
        if self.code {
            chosen.push(clients::Client::ClaudeCode);
        }
        if self.cursor {
            chosen.push(clients::Client::Cursor);
        }
        if self.windsurf {
            chosen.push(clients::Client::Windsurf);
        }
        if self.continue_ext {
            chosen.push(clients::Client::Continue);
        }
        if self.zed {
            chosen.push(clients::Client::Zed);
        }
        if self.codex {
            chosen.push(clients::Client::Codex);
        }
        clients::RegisterSelection {
            clients: chosen,
            all: self.all,
        }
    }
}

/// `clap`-friendly mirror of [`SecretKind`]. Kept separate so we control
/// the `value_enum` derivation independently of the on-disk format.
#[derive(Debug, Clone, Copy, ValueEnum)]
#[clap(rename_all = "snake_case")]
pub enum KindArg {
    /// Generic API key.
    ApiKey,
    /// OAuth bearer / refresh token.
    OauthToken,
    /// Database connection URL.
    DbUrl,
    /// SSH private key.
    SshKey,
    /// Anything else.
    Other,
}

impl From<KindArg> for SecretKind {
    fn from(k: KindArg) -> Self {
        match k {
            KindArg::ApiKey => SecretKind::ApiKey,
            KindArg::OauthToken => SecretKind::OAuthToken,
            KindArg::DbUrl => SecretKind::DbUrl,
            KindArg::SshKey => SecretKind::SshKey,
            KindArg::Other => SecretKind::Other,
        }
    }
}

// -------------------------------------------------------------------------
// Entry point
// -------------------------------------------------------------------------

/// Parse argv, dispatch to a subcommand, and translate `Result` into the
/// project-specific exit-code convention.
pub fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let ctx = Context::from(&cli);

    // First-use trigger: if a vault-requiring command is invoked but no
    // vault exists, run `cloak setup` first. We do NOT auto-trigger for
    // non-stateful commands (init, setup, doctor, completions, daemon
    // primitives) so that scripted callers and the wizard itself don't
    // recurse.
    if requires_vault(&cli.command) && !vault_exists(&ctx) {
        eprintln!(
            "(no vault found at {} — running setup wizard first)",
            ctx.vault_path.display()
        );
        setup::run(
            &ctx,
            setup::SetupOptions {
                non_interactive: false,
                ..Default::default()
            },
        )?;
        eprintln!();
    }

    let outcome: Result<ExitCode> = match cli.command {
        Command::Setup {
            skip_daemon,
            skip_clients,
            skip_env,
            from_dxt,
        } => setup::run(
            &ctx,
            setup::SetupOptions {
                non_interactive: false,
                skip_daemon,
                skip_clients,
                skip_env,
                from_dxt,
            },
        )
        .map(|_| ExitCode::SUCCESS),
        Command::Doctor => doctor::run_with_exit(&ctx),
        Command::Init => init::run(&ctx).map(|_| ExitCode::SUCCESS),
        Command::Add { name, kind, tags } => {
            add::run(&ctx, &name, kind.into(), tags).map(|_| ExitCode::SUCCESS)
        }
        Command::Set { name } => set::run(&ctx, &name).map(|_| ExitCode::SUCCESS),
        Command::Get { name } => get::run(&ctx, &name).map(|_| ExitCode::SUCCESS),
        Command::List => list::run(&ctx).map(|_| ExitCode::SUCCESS),
        Command::Rm {
            name,
            yes,
            tag,
            all,
        } => {
            let sel = if all {
                rm::Selector::All
            } else if let Some(t) = tag {
                rm::Selector::Tag(t)
            } else if let Some(n) = name {
                rm::Selector::Name(n)
            } else {
                return Ok(ExitCode::from(2));
            };
            rm::run(&ctx, sel, yes).map(|_| ExitCode::SUCCESS)
        }
        Command::Show {
            name,
            allow_redirect,
            newline,
        } => show::run(&ctx, &name, allow_redirect, newline).map(|_| ExitCode::SUCCESS),
        Command::Status => status::run(&ctx).map(|_| ExitCode::SUCCESS),
        Command::Completions { shell } => completions::run(shell).map(|_| ExitCode::SUCCESS),
        Command::DaemonUnlock => daemon_unlock::run(&ctx).map(|_| ExitCode::SUCCESS),
        Command::Import {
            path,
            update,
            replace,
        } => {
            let mode = if replace {
                import::Mode::Replace
            } else if update {
                import::Mode::Update
            } else {
                import::Mode::SafeAdd
            };
            import::run(&ctx, path, mode).map(|_| ExitCode::SUCCESS)
        }
        Command::Export { path, force } => {
            export::run(&ctx, path, force).map(|_| ExitCode::SUCCESS)
        }
        Command::Run { only, command } => run::run(&ctx, only, command),
        Command::Panic => panic::run(&ctx).map(|_| ExitCode::SUCCESS),
        Command::Daemon { cmd } => match cmd {
            DaemonCmd::Install {
                launchd,
                systemd_user,
            } => {
                let f = if launchd {
                    Some(daemon::DaemonFlavour::Launchd)
                } else if systemd_user {
                    Some(daemon::DaemonFlavour::SystemdUser)
                } else {
                    None
                };
                daemon::run_install(&ctx, f).map(|_| ExitCode::SUCCESS)
            }
            DaemonCmd::Start => daemon::run_start(&ctx).map(|_| ExitCode::SUCCESS),
            DaemonCmd::Stop => daemon::run_stop(&ctx).map(|_| ExitCode::SUCCESS),
            DaemonCmd::Status => daemon::run_status(&ctx).map(|_| ExitCode::SUCCESS),
        },
        Command::Claude { cmd } => match cmd {
            ClaudeCmd::Register(f) => {
                clients::run_register(&ctx, f.into_selection()).map(|_| ExitCode::SUCCESS)
            }
            ClaudeCmd::Unregister(f) => {
                clients::run_unregister(&ctx, f.into_selection()).map(|_| ExitCode::SUCCESS)
            }
        },
        Command::Restore => restore::run(&ctx).map(|_| ExitCode::SUCCESS),
        Command::Backup { cmd } => match cmd {
            BackupCmd::Mnemonic => backup::run_mnemonic(&ctx).map(|_| ExitCode::SUCCESS),
            BackupCmd::Verify => backup::run_verify(&ctx).map(|_| ExitCode::SUCCESS),
        },
    };

    Ok(match outcome {
        Ok(code) => code,
        Err(e) => {
            let exit = exit_code_for(&e);
            eprintln!("error: {e}");
            exit
        }
    })
}

/// Whether this command requires an initialized vault. Used by the
/// first-use auto-trigger.
fn requires_vault(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::Add { .. }
            | Command::Set { .. }
            | Command::Get { .. }
            | Command::Show { .. }
            | Command::List
            | Command::Rm { .. }
            | Command::Import { .. }
            | Command::Export { .. }
            | Command::Run { .. }
            | Command::DaemonUnlock
    )
}

fn vault_exists(ctx: &Context) -> bool {
    let Ok(vault) = Vault::open_or_create(&ctx.vault_path) else {
        return false;
    };
    vault.is_initialized().unwrap_or(false)
}

// -------------------------------------------------------------------------
// Shared context + helpers
// -------------------------------------------------------------------------

/// Per-invocation immutable context shared with every subcommand.
pub(crate) struct Context {
    pub vault_path: PathBuf,
    pub no_biometric: bool,
}

impl From<&Cli> for Context {
    fn from(cli: &Cli) -> Self {
        let vault_path = cli
            .vault
            .clone()
            .or_else(|| Vault::default_path().ok())
            .unwrap_or_else(|| PathBuf::from("vault.cloak"));
        Self {
            vault_path,
            no_biometric: cli.no_biometric,
        }
    }
}

/// Open the vault at `ctx.vault_path`, creating its parent directory if
/// needed. The vault may not be initialized yet; callers check
/// `is_initialized()` if they care.
pub(crate) fn open_vault(ctx: &Context) -> Result<Vault> {
    if let Some(parent) = ctx.vault_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                anyhow::anyhow!("failed to create vault directory {}: {e}", parent.display())
            })?;
        }
    }
    Ok(Vault::open_or_create(&ctx.vault_path)?)
}

/// Sentinel error type used to signal "this is a system/config error,
/// exit code 2" up the dispatch path.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub(crate) struct SystemError {
    message: String,
}

impl SystemError {
    pub(crate) fn boxed(msg: impl Into<String>) -> anyhow::Error {
        anyhow::Error::new(Self {
            message: msg.into(),
        })
    }
}

/// Decide on the exit code for an error returned from a command. We
/// distinguish system/config errors (`SystemError`, IO, certain
/// `cloak_core::Error` variants) from user-facing errors (wrong
/// passphrase, secret not found, biometric failed) so scripts can react.
fn exit_code_for(e: &anyhow::Error) -> ExitCode {
    if e.downcast_ref::<SystemError>().is_some() {
        return ExitCode::from(2);
    }
    if let Some(core_err) = e.downcast_ref::<cloak_core::Error>() {
        return match core_err {
            cloak_core::Error::Io(_)
            | cloak_core::Error::Storage(_)
            | cloak_core::Error::Keychain(_)
            | cloak_core::Error::SodiumInit
            | cloak_core::Error::VaultFormat(_)
            | cloak_core::Error::UnsupportedVersion(_)
            | cloak_core::Error::Other(_) => ExitCode::from(2),
            _ => ExitCode::from(1),
        };
    }
    ExitCode::FAILURE
}
