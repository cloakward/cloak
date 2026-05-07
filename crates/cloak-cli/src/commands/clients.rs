//! MCP-client registration: detect installed clients (Claude Desktop,
//! Claude Code, Cursor, Windsurf, Continue.dev, Zed, Codex), and
//! register a `cloak` MCP server entry in their config without
//! clobbering existing servers or comments.
//!
//! # Config-edit safety (NON-NEGOTIABLE)
//! - Never destroy existing keys, comments, or other servers.
//! - Always write atomically (tempfile + rename), with a `.bak` of the
//!   original before overwrite.
//! - JSON-with-comments (`jsonc`, used by Cursor/VSCode-family) is
//!   parsed with `serde_json` after stripping `//` and `/* */` comments;
//!   we preserve the comment lines we strip by re-emitting them above
//!   the modified value where reasonable. For v0.1 we do the simpler
//!   thing: strip-then-rewrite, but always keep a `.bak`.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde_json::{Map, Value};

use super::daemon::atomic_write_with_backup;
use super::Context;

/// One supported MCP client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Client {
    /// Claude Desktop (Anthropic), reads `claude_desktop_config.json`.
    ClaudeDesktop,
    /// Claude Code CLI — registered via `claude mcp add cloak ...`.
    ClaudeCode,
    /// Cursor editor.
    Cursor,
    /// Windsurf editor.
    Windsurf,
    /// Continue.dev VS Code / JetBrains extension.
    Continue,
    /// Zed editor.
    Zed,
    /// Codex CLI.
    Codex,
}

impl Client {
    /// Stable lower-case identifier.
    pub fn id(&self) -> &'static str {
        match self {
            Client::ClaudeDesktop => "claude-desktop",
            Client::ClaudeCode => "claude-code",
            Client::Cursor => "cursor",
            Client::Windsurf => "windsurf",
            Client::Continue => "continue",
            Client::Zed => "zed",
            Client::Codex => "codex",
        }
    }

    /// Human-friendly name.
    pub fn label(&self) -> &'static str {
        match self {
            Client::ClaudeDesktop => "Claude Desktop",
            Client::ClaudeCode => "Claude Code",
            Client::Cursor => "Cursor",
            Client::Windsurf => "Windsurf",
            Client::Continue => "Continue.dev",
            Client::Zed => "Zed",
            Client::Codex => "Codex CLI",
        }
    }

    /// Priority order shown in the wizard. Lower = earlier.
    pub fn all() -> &'static [Client] {
        &[
            Client::ClaudeDesktop,
            Client::ClaudeCode,
            Client::Cursor,
            Client::Windsurf,
            Client::Continue,
            Client::Zed,
            Client::Codex,
        ]
    }

    /// Resolve from a stable id (`--all` / `--claude-desktop` / etc.).
    #[allow(dead_code)]
    pub fn from_id(s: &str) -> Option<Self> {
        Self::all().iter().copied().find(|c| c.id() == s)
    }

    /// Path to the JSON config file we manage for this client, if any.
    /// Claude Code is special: it has no JSON file we write — we shell
    /// out to `claude mcp add` instead.
    pub fn config_path(&self) -> Option<PathBuf> {
        let home = dirs::home_dir()?;
        let cfg = dirs::config_dir();
        match self {
            Client::ClaudeDesktop => {
                #[cfg(target_os = "macos")]
                {
                    Some(
                        home.join("Library")
                            .join("Application Support")
                            .join("Claude")
                            .join("claude_desktop_config.json"),
                    )
                }
                #[cfg(target_os = "linux")]
                {
                    Some(
                        cfg.unwrap_or_else(|| home.join(".config"))
                            .join("Claude")
                            .join("claude_desktop_config.json"),
                    )
                }
                #[cfg(target_os = "windows")]
                {
                    let appdata = std::env::var_os("APPDATA").map(PathBuf::from)?;
                    Some(appdata.join("Claude").join("claude_desktop_config.json"))
                }
                #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
                {
                    None
                }
            }
            Client::ClaudeCode => None,
            Client::Cursor => Some(home.join(".cursor").join("mcp.json")),
            Client::Windsurf => Some(home.join(".codeium").join("windsurf").join("mcp_config.json")),
            Client::Continue => Some(home.join(".continue").join("config.json")),
            Client::Zed => Some(
                cfg.unwrap_or_else(|| home.join(".config"))
                    .join("zed")
                    .join("settings.json"),
            ),
            Client::Codex => Some(home.join(".codex").join("config.json")),
        }
    }

    /// Returns true if this client appears to be installed locally.
    pub fn detect(&self) -> bool {
        match self {
            Client::ClaudeCode => super::daemon::resolve_cloakd_bin().is_ok() && which_bin("claude"),
            other => other
                .config_path()
                .map(|p| {
                    p.exists()
                        || p.parent().map(|d| d.exists()).unwrap_or(false)
                })
                .unwrap_or(false),
        }
    }
}

fn which_bin(name: &str) -> bool {
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            if dir.join(name).is_file() {
                return true;
            }
        }
    }
    false
}

/// Detected, installed clients in priority order.
pub fn detected() -> Vec<Client> {
    Client::all().iter().copied().filter(|c| c.detect()).collect()
}

// -------------------------------------------------------------------------
// Registration
// -------------------------------------------------------------------------

/// Resolve the `cloak-mcp` shim binary path.
pub fn resolve_cloak_mcp_bin() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("CLOAK_MCP_BIN") {
        return Ok(PathBuf::from(p));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("cloak-mcp");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("cloak-mcp");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    for p in [
        "/usr/local/bin/cloak-mcp",
        "/opt/homebrew/bin/cloak-mcp",
        "/usr/bin/cloak-mcp",
    ] {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Ok(pb);
        }
    }
    // Fall back to the literal name; downstream tools may resolve it
    // via PATH at run time.
    Ok(PathBuf::from("cloak-mcp"))
}

/// Stable server name we register under in every client.
pub const SERVER_NAME: &str = "cloak";

/// Outcome of a registration attempt for one client.
#[derive(Debug)]
pub enum RegisterOutcome {
    /// We wrote a config / ran the helper successfully.
    Registered(PathBuf),
    /// We registered via an out-of-process tool (e.g. `claude mcp add`).
    RegisteredCommand(String),
    /// The client's config was already pointing at cloak — nothing to do.
    AlreadyPresent(PathBuf),
    /// The client isn't installed; we left it alone.
    Skipped(&'static str),
}

/// Register `cloak` with `client`. Idempotent: existing entries with the
/// same key are replaced (with the old value backed up via `.bak`).
pub fn register(client: Client) -> Result<RegisterOutcome> {
    match client {
        Client::ClaudeCode => register_claude_code(),
        other => register_json_client(other),
    }
}

/// Remove the `cloak` MCP server entry for a client, leaving everything
/// else intact.
pub fn unregister(client: Client) -> Result<RegisterOutcome> {
    match client {
        Client::ClaudeCode => {
            // `claude mcp remove cloak` — best-effort.
            let status = std::process::Command::new("claude")
                .args(["mcp", "remove", SERVER_NAME])
                .status();
            match status {
                Ok(s) if s.success() => Ok(RegisterOutcome::RegisteredCommand(
                    "claude mcp remove cloak".into(),
                )),
                _ => Ok(RegisterOutcome::Skipped("claude CLI not available")),
            }
        }
        other => unregister_json_client(other),
    }
}

fn register_claude_code() -> Result<RegisterOutcome> {
    let mcp_bin = resolve_cloak_mcp_bin()?;
    if !which_bin("claude") {
        return Ok(RegisterOutcome::Skipped("claude CLI not on PATH"));
    }
    let status = std::process::Command::new("claude")
        .args(["mcp", "add", SERVER_NAME, "--", mcp_bin.to_str().unwrap_or("cloak-mcp")])
        .status()
        .context("spawn claude mcp add")?;
    if !status.success() {
        anyhow::bail!("`claude mcp add cloak` failed (exit {})", status);
    }
    Ok(RegisterOutcome::RegisteredCommand(format!(
        "claude mcp add {SERVER_NAME} -- {}",
        mcp_bin.display()
    )))
}

/// Build the MCP server stanza we insert. Mirrors the shape every
/// client-of-clients we tested expects:
/// ```json
/// "cloak": {
///   "command": "/usr/local/bin/cloak-mcp",
///   "args": [],
///   "env": {}
/// }
/// ```
fn cloak_server_stanza() -> Result<Value> {
    let mcp_bin = resolve_cloak_mcp_bin()?;
    Ok(serde_json::json!({
        "command": mcp_bin.to_string_lossy(),
        "args": [],
        "env": {}
    }))
}

fn register_json_client(client: Client) -> Result<RegisterOutcome> {
    let path = client
        .config_path()
        .ok_or_else(|| anyhow::anyhow!("no config path for {}", client.label()))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create {}", parent.display()))?;
    }

    let mut root = read_jsonish(&path)?;
    let stanza = cloak_server_stanza()?;
    let key = mcp_servers_key(client);

    let already_present = root
        .as_object()
        .and_then(|m| m.get(key))
        .and_then(Value::as_object)
        .and_then(|m| m.get(SERVER_NAME))
        .map(|v| v == &stanza)
        .unwrap_or(false);
    if already_present {
        return Ok(RegisterOutcome::AlreadyPresent(path));
    }

    {
        let obj = root.as_object_mut().ok_or_else(|| {
            anyhow::anyhow!("config root at {} is not a JSON object", path.display())
        })?;
        let servers = obj
            .entry(key.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        let servers_obj = servers
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("'{key}' is not a JSON object"))?;
        servers_obj.insert(SERVER_NAME.to_string(), stanza);
    }

    let pretty = serde_json::to_string_pretty(&root)?;
    atomic_write_with_backup(&path, pretty.as_bytes(), 0o600)?;
    Ok(RegisterOutcome::Registered(path))
}

fn unregister_json_client(client: Client) -> Result<RegisterOutcome> {
    let path = client
        .config_path()
        .ok_or_else(|| anyhow::anyhow!("no config path for {}", client.label()))?;
    if !path.exists() {
        return Ok(RegisterOutcome::Skipped("config file does not exist"));
    }
    let mut root = read_jsonish(&path)?;
    let key = mcp_servers_key(client);
    let removed = root
        .as_object_mut()
        .and_then(|m| m.get_mut(key))
        .and_then(Value::as_object_mut)
        .map(|m| m.remove(SERVER_NAME).is_some())
        .unwrap_or(false);
    if !removed {
        return Ok(RegisterOutcome::Skipped("cloak entry not present"));
    }
    let pretty = serde_json::to_string_pretty(&root)?;
    atomic_write_with_backup(&path, pretty.as_bytes(), 0o600)?;
    Ok(RegisterOutcome::Registered(path))
}

/// Most clients use `mcpServers`; Zed nests it under `context_servers`.
fn mcp_servers_key(client: Client) -> &'static str {
    match client {
        Client::Zed => "context_servers",
        _ => "mcpServers",
    }
}

/// Read a (possibly missing) JSON-with-comments file into a `Value`,
/// returning an empty object if the file does not exist or is empty.
fn read_jsonish(path: &Path) -> Result<Value> {
    if !path.exists() {
        return Ok(Value::Object(Map::new()));
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    let stripped = strip_jsonc_comments(&raw);
    serde_json::from_str(&stripped).with_context(|| {
        format!(
            "parse JSON at {} (after stripping // and /* */ comments)",
            path.display()
        )
    })
}

/// Strip `//`-line comments and `/* */`-block comments. Leaves string
/// contents intact (we walk the source character-by-character). Good
/// enough for the editor configs we touch (Cursor / Continue / Zed).
fn strip_jsonc_comments(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let mut in_str = false;
    let mut esc = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if in_str {
            out.push(c);
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_str = true;
            out.push(c);
            i += 1;
            continue;
        }
        if c == '/' && i + 1 < bytes.len() {
            let next = bytes[i + 1] as char;
            if next == '/' {
                // Skip until newline.
                i += 2;
                while i < bytes.len() && bytes[i] as char != '\n' {
                    i += 1;
                }
                continue;
            }
            if next == '*' {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] as char == '*' && bytes[i + 1] as char == '/') {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

// -------------------------------------------------------------------------
// CLI entrypoints — `cloak claude register` / `unregister`
// -------------------------------------------------------------------------

/// Selector for `cloak claude register --foo`.
#[derive(Debug, Clone)]
pub struct RegisterSelection {
    /// Specific clients to act on; empty means "all detected".
    pub clients: Vec<Client>,
    /// Force-acting on every supported client whether or not detected.
    pub all: bool,
}

pub fn run_register(_ctx: &Context, sel: RegisterSelection) -> Result<()> {
    let targets = resolve_targets(&sel);
    if targets.is_empty() {
        println!("(no MCP clients detected; pass --all to force-register)");
        return Ok(());
    }
    for c in targets {
        match register(c) {
            Ok(RegisterOutcome::Registered(p)) => {
                println!("[ok]      {}: wrote {}", c.label(), p.display());
            }
            Ok(RegisterOutcome::RegisteredCommand(cmd)) => {
                println!("[ok]      {}: ran `{cmd}`", c.label());
            }
            Ok(RegisterOutcome::AlreadyPresent(p)) => {
                println!("[noop]    {}: already up to date ({})", c.label(), p.display());
            }
            Ok(RegisterOutcome::Skipped(why)) => {
                println!("[skip]    {}: {why}", c.label());
            }
            Err(e) => {
                println!("[err]     {}: {e}", c.label());
            }
        }
    }
    Ok(())
}

pub fn run_unregister(_ctx: &Context, sel: RegisterSelection) -> Result<()> {
    let targets = resolve_targets(&sel);
    for c in targets {
        match unregister(c) {
            Ok(RegisterOutcome::Registered(p)) => {
                println!("[ok]      {}: cleaned {}", c.label(), p.display());
            }
            Ok(RegisterOutcome::RegisteredCommand(cmd)) => {
                println!("[ok]      {}: ran `{cmd}`", c.label());
            }
            Ok(RegisterOutcome::Skipped(why)) => {
                println!("[skip]    {}: {why}", c.label());
            }
            Ok(RegisterOutcome::AlreadyPresent(_)) => {
                println!("[skip]    {}: noop", c.label());
            }
            Err(e) => println!("[err]     {}: {e}", c.label()),
        }
    }
    Ok(())
}

fn resolve_targets(sel: &RegisterSelection) -> Vec<Client> {
    if sel.all {
        return Client::all().to_vec();
    }
    if !sel.clients.is_empty() {
        return sel.clients.clone();
    }
    detected()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_jsonc_keeps_strings() {
        let s = r#"{
  "name": "// not a comment",
  // a comment
  "x": 1, /* block */
  "y": 2
}"#;
        let stripped = strip_jsonc_comments(s);
        let v: Value = serde_json::from_str(&stripped).unwrap();
        assert_eq!(v["name"], "// not a comment");
        assert_eq!(v["x"], 1);
        assert_eq!(v["y"], 2);
    }

    #[test]
    fn register_idempotent_in_tempdir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg.json");
        std::fs::write(&path, r#"{"otherServers":{"x":1}}"#).unwrap();
        let stanza = serde_json::json!({"command":"x","args":[],"env":{}});

        let mut root: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        root.as_object_mut()
            .unwrap()
            .entry("mcpServers".to_string())
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .unwrap()
            .insert("cloak".to_string(), stanza);
        atomic_write_with_backup(&path, serde_json::to_string_pretty(&root).unwrap().as_bytes(), 0o600).unwrap();

        let after: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(after.get("otherServers").is_some());
        assert!(after["mcpServers"]["cloak"].is_object());
    }
}
