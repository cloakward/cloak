//! `cloak import [PATH] [--update] [--replace]` — load a `.env` file.
//!
//! Default mode: refuse to write if the vault already contains *any*
//! secrets. `--update` adds new keys and overwrites existing values.
//! `--replace` is `--update` + delete entries that aren't in the file.

use std::path::{Path, PathBuf};

use anyhow::Result;
use cloak_core::crypto::Secret;
use cloak_core::vault::SecretKind;
use cloak_core::Error;

use super::audit_log;
use super::dotenv::{parse_dotenv, EnvEntry};
use super::{open_vault, unlock::unlock_interactive, Context};

/// Conflict policy for `cloak import`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Refuse if any keys already exist in the vault.
    SafeAdd,
    /// Add new + overwrite values for existing keys.
    Update,
    /// Update + delete vault entries that aren't in the file.
    Replace,
}

pub fn run(ctx: &Context, path: Option<PathBuf>, mode: Mode) -> Result<()> {
    let path = path.unwrap_or_else(|| PathBuf::from(".env"));
    let entries = parse_dotenv(&path)?;
    if entries.is_empty() {
        println!("(no entries found in {})", path.display());
        return Ok(());
    }

    let mut vault = open_vault(ctx)?;
    if !vault.is_initialized()? {
        anyhow::bail!("vault not initialized — run `cloak setup` first");
    }
    unlock_interactive(&mut vault)?;

    let existing: Vec<String> = vault.list()?.into_iter().map(|m| m.name).collect();
    let existing_set: std::collections::HashSet<&str> =
        existing.iter().map(|s| s.as_str()).collect();

    if mode == Mode::SafeAdd {
        let collisions: Vec<&str> = entries
            .iter()
            .filter(|e| existing_set.contains(e.key.as_str()))
            .map(|e| e.key.as_str())
            .collect();
        if !collisions.is_empty() {
            anyhow::bail!(
                "{} key(s) already exist in vault: {}. Use --update to overwrite or --replace to mirror the file.",
                collisions.len(),
                collisions.join(", ")
            );
        }
    }

    let mut added = 0u32;
    let mut updated = 0u32;
    for e in &entries {
        let val = Secret::new(e.value.clone());
        if existing_set.contains(e.key.as_str()) {
            if mode == Mode::SafeAdd {
                continue;
            }
            vault.set(&e.key, &val)?;
            updated += 1;
            audit_log::append(
                "cli.import",
                Some(&e.key),
                cloak_core::audit::AuditResult::Ok,
                Some("update".into()),
            );
        } else {
            match vault.add(&e.key, SecretKind::ApiKey, vec!["imported".into()], &val) {
                Ok(()) => {
                    added += 1;
                    audit_log::append(
                        "cli.import",
                        Some(&e.key),
                        cloak_core::audit::AuditResult::Ok,
                        Some("add".into()),
                    );
                }
                Err(Error::SecretExists(_)) => {
                    // Race or duplicate keys in the file: treat as update.
                    vault.set(&e.key, &val)?;
                    updated += 1;
                }
                Err(other) => return Err(other.into()),
            }
        }
    }

    let mut removed = 0u32;
    if mode == Mode::Replace {
        let imported: std::collections::HashSet<&str> =
            entries.iter().map(|e| e.key.as_str()).collect();
        for n in &existing {
            if !imported.contains(n.as_str()) {
                vault.rm(n)?;
                removed += 1;
                audit_log::append(
                    "cli.import",
                    Some(n),
                    cloak_core::audit::AuditResult::Ok,
                    Some("replace-delete".into()),
                );
            }
        }
    }

    println!(
        "imported: {added} added, {updated} updated{}",
        if mode == Mode::Replace {
            format!(", {removed} removed")
        } else {
            String::new()
        }
    );
    Ok(())
}

/// Library-mode helper used by the setup wizard.
pub fn import_silently(
    ctx: &Context,
    path: &Path,
    mode: Mode,
) -> Result<(u32, u32, Vec<EnvEntry>)> {
    let entries = parse_dotenv(path)?;
    if entries.is_empty() {
        return Ok((0, 0, entries));
    }
    let mut vault = open_vault(ctx)?;
    unlock_interactive(&mut vault)?;
    let existing: Vec<String> = vault.list()?.into_iter().map(|m| m.name).collect();
    let existing_set: std::collections::HashSet<&str> =
        existing.iter().map(|s| s.as_str()).collect();
    let mut added = 0u32;
    let mut updated = 0u32;
    for e in &entries {
        let val = Secret::new(e.value.clone());
        if existing_set.contains(e.key.as_str()) {
            if mode == Mode::Update || mode == Mode::Replace {
                vault.set(&e.key, &val)?;
                updated += 1;
                audit_log::append(
                    "cli.import",
                    Some(&e.key),
                    cloak_core::audit::AuditResult::Ok,
                    Some("update".into()),
                );
            }
        } else {
            vault.add(&e.key, SecretKind::ApiKey, vec!["imported".into()], &val)?;
            added += 1;
            audit_log::append(
                "cli.import",
                Some(&e.key),
                cloak_core::audit::AuditResult::Ok,
                Some("add".into()),
            );
        }
    }
    Ok((added, updated, entries))
}
