//! `cloak list` — print metadata for every secret. Never plaintext.

use anyhow::Result;

use super::{open_vault, Context};

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

    // Compute column widths so the output is grep-friendly without
    // pulling in a tabular crate.
    let name_w = "NAME"
        .len()
        .max(all.iter().map(|s| s.name.len()).max().unwrap_or(4));
    let kind_w = "KIND"
        .len()
        .max(all.iter().map(|s| s.kind.as_str().len()).max().unwrap_or(4));

    println!(
        "{:<name_w$}  {:<kind_w$}  {:>3}  {:<25}  TAGS",
        "NAME",
        "KIND",
        "VER",
        "UPDATED",
        name_w = name_w,
        kind_w = kind_w,
    );
    for s in &all {
        let tags = if s.tags.is_empty() {
            String::from("-")
        } else {
            s.tags.join(",")
        };
        println!(
            "{:<name_w$}  {:<kind_w$}  {:>3}  {:<25}  {}",
            s.name,
            s.kind.as_str(),
            s.version,
            s.updated_at.to_rfc3339(),
            tags,
            name_w = name_w,
            kind_w = kind_w,
        );
    }
    Ok(())
}
