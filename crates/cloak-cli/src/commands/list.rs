//! `cloak list` — print metadata for every secret. Never plaintext.

use anyhow::Result;
use chrono::Utc;

use super::{open_vault, Context};

const STALE_DAYS: i64 = 90;

/// Print a compact table of secrets sorted by name. Empty vault prints
/// `(no secrets)`. No unlock is required — the data we print is
/// metadata-only.
pub fn run(ctx: &Context) -> Result<()> {
    let vault = open_vault(ctx)?;
    let mut all = vault.list()?;
    all.sort_by(|a, b| a.name.cmp(&b.name));

    if all.is_empty() {
        println!("(no secrets)");
        return Ok(());
    }

    let now = Utc::now();

    let name_w = "NAME"
        .len()
        .max(all.iter().map(|s| s.name.len()).max().unwrap_or(4));
    let kind_w = "KIND"
        .len()
        .max(all.iter().map(|s| s.kind.as_str().len()).max().unwrap_or(4));

    println!(
        "{:<name_w$}  {:<kind_w$}  {:>3}  {:>9}  TAGS",
        "NAME",
        "KIND",
        "VER",
        "AGE",
        name_w = name_w,
        kind_w = kind_w,
    );

    let mut stale = 0u32;
    for s in &all {
        let tags = if s.tags.is_empty() {
            String::from("-")
        } else {
            s.tags.join(",")
        };
        let age_days = (now - s.updated_at).num_days();
        let age_str = format_age(age_days);
        let stale_marker = if age_days >= STALE_DAYS {
            stale += 1;
            "*"
        } else {
            " "
        };
        println!(
            "{:<name_w$}  {:<kind_w$}  {:>3}  {:>9}{} {}",
            s.name,
            s.kind.as_str(),
            s.version,
            age_str,
            stale_marker,
            tags,
            name_w = name_w,
            kind_w = kind_w,
        );
    }
    if stale > 0 {
        eprintln!();
        eprintln!(
            "warning: {stale} secret(s) marked '*' have not been rotated in >{STALE_DAYS} days."
        );
        eprintln!("         Consider running `cloak set NAME` to refresh them.");
    }
    Ok(())
}

fn format_age(days: i64) -> String {
    if days < 0 {
        return "<1d".into();
    }
    if days < 1 {
        return "<1d".into();
    }
    if days < 60 {
        return format!("{days}d");
    }
    let months = days / 30;
    if months < 24 {
        return format!("{months}mo");
    }
    format!("{}y", days / 365)
}
