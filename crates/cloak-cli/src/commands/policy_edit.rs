//! Pure `toml_edit` helpers for adding / removing allowed hosts in the
//! Cloak policy file.
//!
//! These functions operate on a `toml_edit::DocumentMut` in memory so the
//! editing logic is fully testable without touching disk or the daemon.
//! `allow` / `deny` load the document, call one of these, then persist
//! atomically and ask the daemon to reload.
//!
//! Comments and formatting in the existing file are preserved: we only
//! mutate the specific `[[secrets]]` entry (and its nested
//! `[secrets.tools.proxy_authenticated_http_request]` table) for the
//! named secret, creating the tables/array on demand.

use toml_edit::{Array, DocumentMut, Item, Table, Value};

/// The tool whose `allowed_hosts` list `cloak allow` / `cloak deny`
/// manage.
pub(crate) const PROXY_TOOL: &str = "proxy_authenticated_http_request";

/// Outcome of an allow edit.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AllowOutcome {
    /// The host was added (either to a fresh secret block or an existing one).
    Added,
    /// The host was already present; nothing changed.
    AlreadyPresent,
}

/// Outcome of a deny edit.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DenyOutcome {
    /// The host was removed from the secret's allowlist.
    Removed,
    /// The secret had no rule, no proxy block, or the host was absent.
    NotPresent,
}

/// Ensure `[secrets.tools.proxy_authenticated_http_request].allowed_hosts`
/// for `secret` contains `host`. Creates the `[[secrets]]` entry (with
/// `kind = "api_key"`) and the nested tables/array if they are missing.
/// Idempotent: if `host` is already present, returns
/// [`AllowOutcome::AlreadyPresent`] without modifying the document.
pub(crate) fn allow_host(doc: &mut DocumentMut, secret: &str, host: &str) -> AllowOutcome {
    let table = secret_table_mut(doc, secret);
    let hosts = allowed_hosts_array_mut(table);
    if array_contains(hosts, host) {
        return AllowOutcome::AlreadyPresent;
    }
    hosts.push(host);
    AllowOutcome::Added
}

/// Remove `host` from `secret`'s proxy `allowed_hosts`. If the secret
/// rule, the proxy tool block, or the host itself is absent, returns
/// [`DenyOutcome::NotPresent`] without modifying the document.
pub(crate) fn deny_host(doc: &mut DocumentMut, secret: &str, host: &str) -> DenyOutcome {
    let Some(table) = find_secret_table_mut(doc, secret) else {
        return DenyOutcome::NotPresent;
    };
    let Some(hosts) = existing_allowed_hosts_mut(table) else {
        return DenyOutcome::NotPresent;
    };
    let mut removed = false;
    // Walk from the back so index-based removal is stable.
    for i in (0..hosts.len()).rev() {
        if hosts.get(i).and_then(Value::as_str) == Some(host) {
            hosts.remove(i);
            removed = true;
        }
    }
    if removed {
        DenyOutcome::Removed
    } else {
        DenyOutcome::NotPresent
    }
}

// ------------------------------------------------------------------------
// Internals
// ------------------------------------------------------------------------

/// Find the `[[secrets]]` array-of-tables entry whose `name == secret`,
/// returning a mutable reference if present.
fn find_secret_table_mut<'a>(doc: &'a mut DocumentMut, secret: &str) -> Option<&'a mut Table> {
    let arr = doc.get_mut("secrets")?.as_array_of_tables_mut()?;
    arr.iter_mut()
        .find(|t| t.get("name").and_then(Item::as_str) == Some(secret))
}

/// Like [`find_secret_table_mut`] but appends a new entry (with
/// `name = secret`, `kind = "api_key"`) when none exists, and always
/// returns a mutable reference to the matching table.
fn secret_table_mut<'a>(doc: &'a mut DocumentMut, secret: &str) -> &'a mut Table {
    // Ensure the array-of-tables exists.
    if doc.get("secrets").and_then(Item::as_array_of_tables).is_none() {
        doc["secrets"] = Item::ArrayOfTables(toml_edit::ArrayOfTables::new());
    }
    let arr = doc["secrets"].as_array_of_tables_mut().expect("secrets aot");

    let existing_idx = arr
        .iter()
        .position(|t| t.get("name").and_then(Item::as_str) == Some(secret));
    let idx = match existing_idx {
        Some(i) => i,
        None => {
            let mut t = Table::new();
            t.insert("name", toml_edit::value(secret));
            t.insert("kind", toml_edit::value("api_key"));
            arr.push(t);
            arr.len() - 1
        }
    };
    arr.get_mut(idx).expect("secret table just located")
}

/// Get (creating if needed) the `allowed_hosts` array inside the secret
/// table's `[tools.proxy_authenticated_http_request]` block.
fn allowed_hosts_array_mut(table: &mut Table) -> &mut Array {
    // tools
    if table.get("tools").and_then(Item::as_table).is_none() {
        let mut t = Table::new();
        t.set_implicit(true);
        table.insert("tools", Item::Table(t));
    }
    let tools = table["tools"].as_table_mut().expect("tools table");
    tools.set_implicit(true);

    // tools.<PROXY_TOOL>
    if tools.get(PROXY_TOOL).and_then(Item::as_table).is_none() {
        tools.insert(PROXY_TOOL, Item::Table(Table::new()));
    }
    let proxy = tools[PROXY_TOOL].as_table_mut().expect("proxy tool table");

    // allowed_hosts
    if proxy.get("allowed_hosts").and_then(Item::as_array).is_none() {
        proxy.insert("allowed_hosts", toml_edit::value(Array::new()));
    }
    proxy["allowed_hosts"]
        .as_array_mut()
        .expect("allowed_hosts array")
}

/// Mutable reference to an existing `allowed_hosts` array, or `None` if
/// the proxy tool block / array is absent. Never creates anything.
fn existing_allowed_hosts_mut(table: &mut Table) -> Option<&mut Array> {
    table
        .get_mut("tools")?
        .as_table_mut()?
        .get_mut(PROXY_TOOL)?
        .as_table_mut()?
        .get_mut("allowed_hosts")?
        .as_array_mut()
}

fn array_contains(arr: &Array, host: &str) -> bool {
    arr.iter().any(|v| v.as_str() == Some(host))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(src: &str) -> DocumentMut {
        src.parse::<DocumentMut>().unwrap()
    }

    fn hosts(doc: &DocumentMut, secret: &str) -> Vec<String> {
        let arr = doc["secrets"].as_array_of_tables().unwrap();
        let t = arr
            .iter()
            .find(|t| t.get("name").and_then(Item::as_str) == Some(secret))
            .unwrap();
        t["tools"][PROXY_TOOL]["allowed_hosts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn allow_adds_host_to_brand_new_secret() {
        let mut doc = parse("[default]\naction = \"deny\"\n");
        let out = allow_host(&mut doc, "STRIPE_SECRET_KEY", "api.stripe.com");
        assert_eq!(out, AllowOutcome::Added);
        assert_eq!(hosts(&doc, "STRIPE_SECRET_KEY"), vec!["api.stripe.com"]);
        // kind defaulted.
        let arr = doc["secrets"].as_array_of_tables().unwrap();
        let t = arr.iter().next().unwrap();
        assert_eq!(t.get("kind").and_then(Item::as_str), Some("api_key"));
    }

    #[test]
    fn allow_appends_to_existing_secret_without_duplicating() {
        let mut doc = parse(
            r#"
[[secrets]]
name = "GITHUB_TOKEN"
kind = "api_key"
[secrets.tools.proxy_authenticated_http_request]
allowed_hosts = ["api.github.com"]
"#,
        );
        let out = allow_host(&mut doc, "GITHUB_TOKEN", "uploads.github.com");
        assert_eq!(out, AllowOutcome::Added);
        assert_eq!(
            hosts(&doc, "GITHUB_TOKEN"),
            vec!["api.github.com", "uploads.github.com"]
        );
    }

    #[test]
    fn allow_is_idempotent() {
        let mut doc = parse(
            r#"
[[secrets]]
name = "GITHUB_TOKEN"
kind = "api_key"
[secrets.tools.proxy_authenticated_http_request]
allowed_hosts = ["api.github.com"]
"#,
        );
        let out = allow_host(&mut doc, "GITHUB_TOKEN", "api.github.com");
        assert_eq!(out, AllowOutcome::AlreadyPresent);
        assert_eq!(hosts(&doc, "GITHUB_TOKEN"), vec!["api.github.com"]);
    }

    #[test]
    fn allow_preserves_comments_and_other_secrets() {
        let original = r#"# top comment
[default]
action = "deny"

[[secrets]]
name = "OTHER"
kind = "api_key"
[secrets.tools.proxy_authenticated_http_request]
allowed_hosts = ["api.other.com"]
"#;
        let mut doc = parse(original);
        allow_host(&mut doc, "STRIPE_SECRET_KEY", "api.stripe.com");
        let rendered = doc.to_string();
        assert!(rendered.contains("# top comment"));
        assert!(rendered.contains("name = \"OTHER\""));
        assert!(rendered.contains("api.other.com"));
        assert!(rendered.contains("STRIPE_SECRET_KEY"));
        assert!(rendered.contains("api.stripe.com"));
    }

    #[test]
    fn deny_removes_a_host() {
        let mut doc = parse(
            r#"
[[secrets]]
name = "GITHUB_TOKEN"
kind = "api_key"
[secrets.tools.proxy_authenticated_http_request]
allowed_hosts = ["api.github.com", "uploads.github.com"]
"#,
        );
        let out = deny_host(&mut doc, "GITHUB_TOKEN", "uploads.github.com");
        assert_eq!(out, DenyOutcome::Removed);
        assert_eq!(hosts(&doc, "GITHUB_TOKEN"), vec!["api.github.com"]);
    }

    #[test]
    fn deny_absent_host_is_noop() {
        let mut doc = parse(
            r#"
[[secrets]]
name = "GITHUB_TOKEN"
kind = "api_key"
[secrets.tools.proxy_authenticated_http_request]
allowed_hosts = ["api.github.com"]
"#,
        );
        let out = deny_host(&mut doc, "GITHUB_TOKEN", "nope.example.com");
        assert_eq!(out, DenyOutcome::NotPresent);
        assert_eq!(hosts(&doc, "GITHUB_TOKEN"), vec!["api.github.com"]);
    }

    #[test]
    fn deny_absent_secret_is_noop() {
        let mut doc = parse("[default]\naction = \"deny\"\n");
        let out = deny_host(&mut doc, "NOSUCH", "api.example.com");
        assert_eq!(out, DenyOutcome::NotPresent);
    }
}
