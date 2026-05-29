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
use crate::prompt::prompt_yes_no;

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

pub fn run(ctx: &Context, path: Option<PathBuf>, mode: Mode, yes: bool) -> Result<()> {
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
    let imported_set: std::collections::HashSet<&str> =
        entries.iter().map(|e| e.key.as_str()).collect();
    let to_remove: Vec<String> = if mode == Mode::Replace {
        existing
            .iter()
            .filter(|n| !imported_set.contains(n.as_str()))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };

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
    if mode == Mode::Replace && !to_remove.is_empty() && !yes {
        let q = format!(
            "import --replace will delete {} secret(s) not present in {}:\n  {}\nproceed?",
            to_remove.len(),
            path.display(),
            to_remove.join(", ")
        );
        if !prompt_yes_no(&q, false)? {
            println!("cancelled");
            return Ok(());
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
            audit_log::append_required(
                "cli.import",
                Some(&e.key),
                cloak_core::audit::AuditResult::Started,
                Some("update".into()),
            )?;
            if let Err(err) = vault.set(&e.key, &val) {
                audit_log::append_required(
                    "cli.import",
                    Some(&e.key),
                    cloak_core::audit::AuditResult::Error,
                    Some("update failed".into()),
                )?;
                return Err(err.into());
            }
            updated += 1;
            audit_log::append_required(
                "cli.import",
                Some(&e.key),
                cloak_core::audit::AuditResult::Ok,
                Some("update".into()),
            )?;
        } else {
            audit_log::append_required(
                "cli.import",
                Some(&e.key),
                cloak_core::audit::AuditResult::Started,
                Some("add".into()),
            )?;
            match vault.add(&e.key, SecretKind::ApiKey, vec!["imported".into()], &val) {
                Ok(()) => {
                    added += 1;
                    audit_log::append_required(
                        "cli.import",
                        Some(&e.key),
                        cloak_core::audit::AuditResult::Ok,
                        Some("add".into()),
                    )?;
                }
                Err(Error::SecretExists(_)) => {
                    audit_log::append_required(
                        "cli.import",
                        Some(&e.key),
                        cloak_core::audit::AuditResult::Error,
                        Some("add raced with existing secret".into()),
                    )?;
                    audit_log::append_required(
                        "cli.import",
                        Some(&e.key),
                        cloak_core::audit::AuditResult::Started,
                        Some("update-after-add-race".into()),
                    )?;
                    // Race or duplicate keys in the file: treat as update.
                    if let Err(err) = vault.set(&e.key, &val) {
                        audit_log::append_required(
                            "cli.import",
                            Some(&e.key),
                            cloak_core::audit::AuditResult::Error,
                            Some("update-after-add-race failed".into()),
                        )?;
                        return Err(err.into());
                    }
                    updated += 1;
                    audit_log::append_required(
                        "cli.import",
                        Some(&e.key),
                        cloak_core::audit::AuditResult::Ok,
                        Some("update-after-add-race".into()),
                    )?;
                }
                Err(other) => {
                    audit_log::append_required(
                        "cli.import",
                        Some(&e.key),
                        cloak_core::audit::AuditResult::Error,
                        Some("add failed".into()),
                    )?;
                    return Err(other.into());
                }
            }
        }
    }

    let mut removed = 0u32;
    if mode == Mode::Replace {
        for n in &to_remove {
            audit_log::append_required(
                "cli.import",
                Some(n),
                cloak_core::audit::AuditResult::Started,
                Some("replace-delete".into()),
            )?;
            if let Err(e) = vault.rm(n) {
                audit_log::append_required(
                    "cli.import",
                    Some(n),
                    cloak_core::audit::AuditResult::Error,
                    Some("replace-delete failed".into()),
                )?;
                return Err(e.into());
            }
            removed += 1;
            audit_log::append_required(
                "cli.import",
                Some(n),
                cloak_core::audit::AuditResult::Ok,
                Some("replace-delete".into()),
            )?;
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
                audit_log::append_required(
                    "cli.import",
                    Some(&e.key),
                    cloak_core::audit::AuditResult::Started,
                    Some("update".into()),
                )?;
                if let Err(err) = vault.set(&e.key, &val) {
                    audit_log::append_required(
                        "cli.import",
                        Some(&e.key),
                        cloak_core::audit::AuditResult::Error,
                        Some("update failed".into()),
                    )?;
                    return Err(err.into());
                }
                updated += 1;
                audit_log::append_required(
                    "cli.import",
                    Some(&e.key),
                    cloak_core::audit::AuditResult::Ok,
                    Some("update".into()),
                )?;
            }
        } else {
            audit_log::append_required(
                "cli.import",
                Some(&e.key),
                cloak_core::audit::AuditResult::Started,
                Some("add".into()),
            )?;
            if let Err(err) = vault.add(&e.key, SecretKind::ApiKey, vec!["imported".into()], &val) {
                audit_log::append_required(
                    "cli.import",
                    Some(&e.key),
                    cloak_core::audit::AuditResult::Error,
                    Some("add failed".into()),
                )?;
                return Err(err.into());
            }
            added += 1;
            audit_log::append_required(
                "cli.import",
                Some(&e.key),
                cloak_core::audit::AuditResult::Ok,
                Some("add".into()),
            )?;
        }
    }
    Ok((added, updated, entries))
}
