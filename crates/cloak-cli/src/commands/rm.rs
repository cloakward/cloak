//! `cloak rm` — single-name, `--tag TAG`, and `--all` removal.

use anyhow::Result;
use cloak_core::Error;

use super::{open_vault, unlock::unlock_interactive, Context, SystemError};
use crate::biometric_macos;
use crate::prompt::prompt_yes_no;

/// Selector for which secrets to delete.
#[derive(Debug, Clone)]
pub enum Selector {
    /// A single named secret.
    Name(String),
    /// Every secret carrying `tag`.
    Tag(String),
    /// Wipe the entire vault.
    All,
}

pub fn run(ctx: &Context, sel: Selector, yes: bool) -> Result<()> {
    let mut vault = open_vault(ctx)?;
    if !vault.is_initialized()? {
        return Err(SystemError::boxed(
            "vault not initialized — run `cloak setup` first",
        ));
    }
    let all = vault.list()?;
    let targets: Vec<String> = match &sel {
        Selector::Name(n) => {
            if !all.iter().any(|m| &m.name == n) {
                anyhow::bail!("secret not found: {n}");
            }
            vec![n.clone()]
        }
        Selector::Tag(tag) => all
            .iter()
            .filter(|m| m.tags.iter().any(|t| t == tag))
            .map(|m| m.name.clone())
            .collect(),
        Selector::All => all.iter().map(|m| m.name.clone()).collect(),
    };

    if targets.is_empty() {
        match &sel {
            Selector::Tag(t) => println!("(no secrets with tag '{t}')"),
            Selector::All => println!("(vault is empty)"),
            _ => {}
        }
        return Ok(());
    }

    // Prompt summary, unless --yes.
    if !yes {
        let q = match &sel {
            Selector::Name(_) => format!("delete '{}'?", targets[0]),
            Selector::Tag(t) => format!(
                "delete {} secret(s) tagged '{t}'?\n  {}\nproceed?",
                targets.len(),
                targets.join(", ")
            ),
            Selector::All => format!(
                "DELETE ALL {} secret(s) in this vault? This cannot be undone.",
                targets.len()
            ),
        };
        if !prompt_yes_no(&q, false)? {
            println!("cancelled");
            return Ok(());
        }
    }

    // `--all` requires extra-strong confirmation: typed passphrase
    // (re-confirms ownership) plus Touch ID/polkit.
    if matches!(sel, Selector::All) {
        unlock_interactive(&mut vault)?;
        if !ctx.no_biometric {
            match biometric_macos::authenticate(
                "Confirm: delete every secret in the Cloak vault",
            ) {
                Ok(true) => {}
                _ => anyhow::bail!("biometric confirmation failed; aborting"),
            }
        }
    } else {
        unlock_interactive(&mut vault)?;
    }

    let mut removed = 0u32;
    for name in &targets {
        match vault.rm(name) {
            Ok(()) => {
                removed += 1;
                super::audit_log::append(
                    "cli.rm",
                    Some(name),
                    cloak_core::audit::AuditResult::Ok,
                    Some(match &sel {
                        Selector::Name(_) => "single".into(),
                        Selector::Tag(t) => format!("tag={t}"),
                        Selector::All => "all".into(),
                    }),
                );
            }
            Err(Error::SecretNotFound(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }
    match &sel {
        Selector::Name(n) => println!("removed: {n}"),
        _ => println!("removed: {removed} secret(s)"),
    }
    Ok(())
}
