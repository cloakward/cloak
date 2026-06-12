//! `cloak policy`: print a readable summary of the active policy file:
//! the default action and, for each `[[secrets]]` rule, its name and the
//! hosts allowed for `proxy_authenticated_http_request`.

use anyhow::{Context as _, Result};
use toml_edit::{DocumentMut, Item};

use cloak_core::policy::default_policy_path;

use super::policy_edit::PROXY_TOOL;
use super::Context;

pub fn run(_ctx: &Context) -> Result<()> {
    let path = default_policy_path();
    if !path.exists() {
        println!(
            "no policy yet (run `cloak setup` to create one at {})",
            path.display()
        );
        return Ok(());
    }

    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("read policy {}", path.display()))?;
    let doc = raw
        .parse::<DocumentMut>()
        .with_context(|| format!("parse policy {}", path.display()))?;

    let default_action = doc
        .get("default")
        .and_then(Item::as_table_like)
        .and_then(|t| t.get("action"))
        .and_then(Item::as_str)
        .unwrap_or("deny");

    println!("policy: {}", path.display());
    println!("default action: {default_action}");

    let secrets = doc.get("secrets").and_then(Item::as_array_of_tables);
    let Some(secrets) = secrets else {
        println!("secrets: (none)");
        return Ok(());
    };
    if secrets.is_empty() {
        println!("secrets: (none)");
        return Ok(());
    }

    println!("secrets:");
    for t in secrets.iter() {
        let name = t.get("name").and_then(Item::as_str).unwrap_or("<unnamed>");
        let hosts: Vec<&str> = t
            .get("tools")
            .and_then(Item::as_table_like)
            .and_then(|tools| tools.get(PROXY_TOOL))
            .and_then(Item::as_table_like)
            .and_then(|proxy| proxy.get("allowed_hosts"))
            .and_then(Item::as_array)
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();

        if hosts.is_empty() {
            println!("  {name}: (no allowed hosts)");
        } else {
            println!("  {name}: {}", hosts.join(", "));
        }
    }
    Ok(())
}
