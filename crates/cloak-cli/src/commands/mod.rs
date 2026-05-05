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

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use cloak_core::vault::{SecretKind, Vault};

mod add;
mod completions;
mod daemon_unlock;
mod get;
mod init;
mod list;
mod rm;
mod set;
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

    /// Remove a secret. Prompts for confirmation unless `--yes`.
    Rm {
        /// Name of the secret to remove.
        name: String,
        /// Skip the confirmation prompt.
        #[arg(short = 'y', long = "yes")]
        yes: bool,
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
    /// can serve requests. v0.1 bridge — see the module docs.
    DaemonUnlock,
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

    let outcome = match cli.command {
        Command::Init => init::run(&ctx),
        Command::Add { name, kind, tags } => add::run(&ctx, &name, kind.into(), tags),
        Command::Set { name } => set::run(&ctx, &name),
        Command::Get { name } => get::run(&ctx, &name),
        Command::List => list::run(&ctx),
        Command::Rm { name, yes } => rm::run(&ctx, &name, yes),
        Command::Show {
            name,
            allow_redirect,
            newline,
        } => show::run(&ctx, &name, allow_redirect, newline),
        Command::Status => status::run(&ctx),
        Command::Completions { shell } => completions::run(shell),
        Command::DaemonUnlock => daemon_unlock::run(&ctx),
    };

    Ok(match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // The command modules are responsible for printing
            // user-friendly messages; we just translate the error class
            // into an exit code. The error itself is also printed to
            // stderr so anyhow's chain is visible in debug runs.
            let exit = exit_code_for(&e);
            eprintln!("error: {e}");
            exit
        }
    })
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
