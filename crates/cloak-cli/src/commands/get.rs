//! `cloak get NAME` — print metadata for a secret. Never plaintext.

use anyhow::Result;
use cloak_core::Error;

use super::{open_vault, Context};

/// Print metadata for a single secret. Does not unlock the vault — only
/// the public `secrets` table columns (name, kind, tags, timestamps,
/// version) are read.
pub fn run(ctx: &Context, name: &str) -> Result<()> {
    let vault = open_vault(ctx)?;
    let md = match vault.get_metadata(name) {
        Ok(m) => m,
        Err(Error::SecretNotFound(_)) => {
            anyhow::bail!("secret not found: {name}");
        }
        Err(other) => return Err(other.into()),
    };

    let tags = if md.tags.is_empty() {
        "-".to_string()
    } else {
        md.tags.join(", ")
    };

    println!("name:       {}", md.name);
    println!("kind:       {}", md.kind.as_str());
    println!("tags:       {tags}");
    println!("created:    {}", md.created_at.to_rfc3339());
    println!("updated:    {}", md.updated_at.to_rfc3339());
    println!("version:    {}", md.version);
    Ok(())
}
