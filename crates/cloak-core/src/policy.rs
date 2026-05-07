//! Policy DSL parser + evaluator.
//!
//! Policies are written in TOML and define:
//! - a global `[default]` action and rate limit
//! - per-tool defaults under `[tools.<name>]`
//! - per-secret overrides under `[[secrets]]`, with optional
//!   `[secrets.tools.<name>]` blocks for fine-grained behavior
//!
//! Evaluation precedence: most-specific matching `[[secrets]]` rule's tool
//! block, then `[tools.<tool>]`, then `[default].action`.
//!
//! Glob matching uses `*` only (no `?`, no character classes). Specificity
//! is the longest non-wildcard prefix; ties are broken by file order.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::Deserialize;

use crate::error::{Error, Result};

/// Default policy file path: `~/.config/cloak/policy.toml` (XDG config
/// dir on Linux, `~/Library/Application Support` on macOS, etc.). Falls
/// back to `/tmp/cloak-policy.toml` only if no config dir is detectable.
///
/// Both `cloakd` (loading the policy at startup) and `cloak setup` /
/// `cloak doctor` (writing / inspecting it) resolve to the same path.
pub fn default_policy_path() -> PathBuf {
    if let Some(cfg) = dirs::config_dir() {
        return cfg.join("cloak").join("policy.toml");
    }
    PathBuf::from("/tmp/cloak-policy.toml")
}

// ------------------------------------------------------------------------
// Schema types
// ------------------------------------------------------------------------

/// Top-level policy document.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Policy {
    /// Global defaults.
    #[serde(default)]
    pub default: Default_,
    /// Per-tool default overrides.
    #[serde(default)]
    pub tools: ToolDefaults,
    /// Per-secret rules; first-match wins after specificity sort.
    #[serde(default)]
    pub secrets: Vec<SecretRule>,
}

/// Outcome decisions a policy can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Allow the call.
    Allow,
    /// Deny the call.
    Deny,
    /// Allow only after explicit user confirmation.
    RequireConfirmation,
}

fn default_action_deny() -> Action {
    Action::Deny
}

/// `[default]` block: fallback action and rate-limit defaults.
#[derive(Debug, Clone, Deserialize)]
pub struct Default_ {
    /// Action when no rule matches.
    #[serde(default = "default_action_deny")]
    pub action: Action,
    /// Default rate limit applied to every (tool, peer, secret) bucket.
    #[serde(default)]
    pub rate_limit: RateLimit,
}

impl Default for Default_ {
    fn default() -> Self {
        Self {
            action: Action::Deny,
            rate_limit: RateLimit::default(),
        }
    }
}

/// Token-bucket parameters.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct RateLimit {
    /// Bucket capacity.
    #[serde(default = "default_burst")]
    pub burst: u32,
    /// Tokens added per minute.
    #[serde(default = "default_refill")]
    pub refill_per_minute: u32,
}

fn default_burst() -> u32 {
    10
}
fn default_refill() -> u32 {
    30
}

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            burst: default_burst(),
            refill_per_minute: default_refill(),
        }
    }
}

/// Per-tool configuration block.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ToolDefaults {
    /// Rule for `proxy_authenticated_http_request`.
    pub proxy_authenticated_http_request: Option<ToolRule>,
    /// Rule for `sign_request`.
    pub sign_request: Option<ToolRule>,
    /// Rule for `mint_short_lived_token`.
    pub mint_short_lived_token: Option<ToolRule>,
    /// Rule for `query_audit`.
    pub query_audit: Option<ToolRule>,
}

/// Settings for a single tool.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ToolRule {
    /// Explicit allow/deny override. `None` falls through to `[default]`.
    pub allow: Option<bool>,
    /// Allowlist of host globs (proxy_http only).
    pub allowed_hosts: Option<Vec<String>>,
    /// Whether to require user confirmation before allowing.
    pub require_confirmation: Option<bool>,
    /// Confirmation prompt timeout in seconds.
    pub confirmation_timeout_seconds: Option<u32>,
}

/// One `[[secrets]]` table.
#[derive(Debug, Clone, Deserialize)]
pub struct SecretRule {
    /// Glob pattern matched against `EvalContext::secret_name`.
    pub name: String,
    /// Optional kind constraint (informational).
    pub kind: Option<String>,
    /// Per-tool overrides for this secret.
    #[serde(default)]
    pub tools: ToolDefaults,
}

// ------------------------------------------------------------------------
// Decision + EvalContext
// ------------------------------------------------------------------------

/// Outcome of an evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Allow / Deny / RequireConfirmation.
    pub action: Action,
    /// Human-readable explanation; never includes secret values.
    pub reason: String,
    /// Path of the matched rule, e.g. `[secrets.AWS_*].tools.sign_request`.
    pub matched_rule: Option<String>,
}

/// All inputs needed to evaluate a single call.
#[derive(Debug, Clone, Copy)]
pub struct EvalContext<'a> {
    /// Canonical tool name, e.g. `proxy_authenticated_http_request`.
    pub tool: &'a str,
    /// Secret name (optional for tools that don't reference a secret).
    pub secret_name: Option<&'a str>,
    /// Secret kind (informational).
    pub secret_kind: Option<&'a str>,
    /// Target host (proxy_http only).
    pub target_host: Option<&'a str>,
    /// Caller basename (used for rate-limit bucketing).
    pub peer_basename: &'a str,
}

// ------------------------------------------------------------------------
// PolicyEngine
// ------------------------------------------------------------------------

/// Stateful policy engine: parses + evaluates + tracks rate-limit buckets.
pub struct PolicyEngine {
    policy: Policy,
    rate: RateLimiter,
}

impl PolicyEngine {
    /// Parse a policy from a TOML string.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(toml_src: &str) -> Result<Self> {
        let policy: Policy =
            toml::from_str(toml_src).map_err(|e| Error::PolicyDenied(format!("parse: {e}")))?;
        let rate = RateLimiter::new(policy.default.rate_limit);
        Ok(Self { policy, rate })
    }

    /// Load a policy from disk. Missing file = default-deny policy.
    pub fn from_path(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(s) => Self::from_str(&s),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                policy: Policy::default(),
                rate: RateLimiter::new(RateLimit::default()),
            }),
            Err(e) => Err(e.into()),
        }
    }

    /// Evaluate a request against the policy.
    pub fn evaluate(&mut self, ctx: &EvalContext<'_>) -> Decision {
        // 1. Find the most-specific matching [[secrets]] rule.
        let secret_match = ctx
            .secret_name
            .and_then(|name| find_matching_secret(&self.policy.secrets, name));

        // 2. From the matched secret rule, look at tool-specific override.
        if let Some((idx, rule)) = secret_match {
            if let Some(tr) = pick_tool_rule(&rule.tools, ctx.tool) {
                if let Some(d) = decide_from_tool_rule(
                    tr,
                    ctx,
                    &format!("[secrets.{}].tools.{}", rule.name, ctx.tool),
                ) {
                    return d;
                }
            }
            let _ = idx; // unused but useful for future debugging
        }

        // 3. Fall through to per-tool defaults.
        if let Some(tr) = pick_tool_rule(&self.policy.tools, ctx.tool) {
            if let Some(d) = decide_from_tool_rule(tr, ctx, &format!("[tools.{}]", ctx.tool)) {
                return d;
            }
        }

        // 4. Default action.
        Decision {
            action: self.policy.default.action,
            reason: format!("default action {:?}", self.policy.default.action),
            matched_rule: None,
        }
    }

    /// Consume one token from the relevant bucket. Returns `false` if the
    /// caller has exceeded their rate.
    pub fn check_rate(&mut self, ctx: &EvalContext<'_>) -> bool {
        let key = format!(
            "{}|{}|{}",
            ctx.tool,
            ctx.peer_basename,
            ctx.secret_name.unwrap_or("*"),
        );
        self.rate.allow(&key)
    }
}

fn pick_tool_rule<'a>(t: &'a ToolDefaults, tool: &str) -> Option<&'a ToolRule> {
    match tool {
        "proxy_authenticated_http_request" => t.proxy_authenticated_http_request.as_ref(),
        "sign_request" => t.sign_request.as_ref(),
        "mint_short_lived_token" => t.mint_short_lived_token.as_ref(),
        "query_audit" => t.query_audit.as_ref(),
        _ => None,
    }
}

/// Convert a [`ToolRule`] into a [`Decision`]. Returns `None` if the rule
/// has nothing decisive to say (no `allow`, no `require_confirmation`, no
/// applicable `allowed_hosts`) and the caller should fall through.
fn decide_from_tool_rule(
    rule: &ToolRule,
    ctx: &EvalContext<'_>,
    rule_path: &str,
) -> Option<Decision> {
    // `allowed_hosts` only applies to proxy_authenticated_http_request.
    if ctx.tool == "proxy_authenticated_http_request" {
        if let Some(hosts) = &rule.allowed_hosts {
            let host = ctx.target_host.unwrap_or("");
            let ok = hosts.iter().any(|pat| glob_match(pat, host));
            if !ok {
                return Some(Decision {
                    action: Action::Deny,
                    reason: format!(
                        "host {} not in allowed_hosts ({} entries)",
                        host,
                        hosts.len()
                    ),
                    matched_rule: Some(rule_path.to_string()),
                });
            }
        }
    }

    if rule.require_confirmation == Some(true) {
        // `allow = false` overrides confirmation.
        if rule.allow == Some(false) {
            return Some(Decision {
                action: Action::Deny,
                reason: "rule sets allow=false".to_string(),
                matched_rule: Some(rule_path.to_string()),
            });
        }
        return Some(Decision {
            action: Action::RequireConfirmation,
            reason: "rule requires confirmation".to_string(),
            matched_rule: Some(rule_path.to_string()),
        });
    }

    match rule.allow {
        Some(true) => Some(Decision {
            action: Action::Allow,
            reason: "rule allows".to_string(),
            matched_rule: Some(rule_path.to_string()),
        }),
        Some(false) => Some(Decision {
            action: Action::Deny,
            reason: "rule denies".to_string(),
            matched_rule: Some(rule_path.to_string()),
        }),
        None => {
            // If allowed_hosts matched (or the rule has only an
            // allowed_hosts list with a hit), treat that as an Allow.
            if ctx.tool == "proxy_authenticated_http_request" && rule.allowed_hosts.is_some() {
                return Some(Decision {
                    action: Action::Allow,
                    reason: "host matched allowed_hosts".to_string(),
                    matched_rule: Some(rule_path.to_string()),
                });
            }
            None
        }
    }
}

/// Find the most-specific matching `[[secrets]]` rule. Specificity =
/// length of the non-wildcard prefix. Ties broken by file order
/// (lower index wins).
fn find_matching_secret<'a>(
    rules: &'a [SecretRule],
    name: &str,
) -> Option<(usize, &'a SecretRule)> {
    let mut best: Option<(usize, usize, &SecretRule)> = None; // (specificity, idx, rule)
    for (i, r) in rules.iter().enumerate() {
        if !glob_match(&r.name, name) {
            continue;
        }
        let spec = non_wildcard_prefix_len(&r.name);
        match best {
            None => best = Some((spec, i, r)),
            Some((bspec, bidx, _)) => {
                if spec > bspec || (spec == bspec && i < bidx) {
                    best = Some((spec, i, r));
                }
            }
        }
    }
    best.map(|(_, i, r)| (i, r))
}

fn non_wildcard_prefix_len(pat: &str) -> usize {
    pat.chars().take_while(|c| *c != '*').count()
}

/// Match a `*`-glob. The only wildcard is `*` (matches any number of any
/// chars). No `?`, no character classes. Anchored on both sides.
fn glob_match(pat: &str, s: &str) -> bool {
    // Iterative two-pointer with backtracking. O(|pat| * |s|) worst case.
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = s.chars().collect();
    let (mut i, mut j) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut star_j: usize = 0;
    while j < t.len() {
        if i < p.len() && p[i] == '*' {
            star = Some(i);
            star_j = j;
            i += 1;
        } else if i < p.len() && p[i] == t[j] {
            i += 1;
            j += 1;
        } else if let Some(si) = star {
            i = si + 1;
            star_j += 1;
            j = star_j;
        } else {
            return false;
        }
    }
    while i < p.len() && p[i] == '*' {
        i += 1;
    }
    i == p.len()
}

// ------------------------------------------------------------------------
// RateLimiter (token bucket)
// ------------------------------------------------------------------------

struct Bucket {
    tokens: f64,
    last: Instant,
}

struct RateLimiter {
    cfg: RateLimit,
    buckets: HashMap<String, Bucket>,
}

impl RateLimiter {
    fn new(cfg: RateLimit) -> Self {
        Self {
            cfg,
            buckets: HashMap::new(),
        }
    }

    fn allow(&mut self, key: &str) -> bool {
        let cap = self.cfg.burst as f64;
        let per_sec = self.cfg.refill_per_minute as f64 / 60.0;
        let now = Instant::now();
        let b = self.buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: cap,
            last: now,
        });
        let dt = now.saturating_duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + dt * per_sec).min(cap);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ------------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(tool: &'a str, secret: Option<&'a str>) -> EvalContext<'a> {
        EvalContext {
            tool,
            secret_name: secret,
            secret_kind: None,
            target_host: None,
            peer_basename: "test",
        }
    }

    fn ctx_host<'a>(tool: &'a str, secret: Option<&'a str>, host: &'a str) -> EvalContext<'a> {
        EvalContext {
            tool,
            secret_name: secret,
            secret_kind: None,
            target_host: Some(host),
            peer_basename: "test",
        }
    }

    // ---- Glob matcher --------------------------------------------------

    #[test]
    fn glob_exact() {
        assert!(glob_match("AWS_DEPLOY_KEY", "AWS_DEPLOY_KEY"));
        assert!(!glob_match("AWS_DEPLOY_KEY", "AWS_DEPLOY"));
    }

    #[test]
    fn glob_prefix_star() {
        assert!(glob_match("AWS_*", "AWS_DEPLOY_KEY"));
        assert!(!glob_match("AWS_*", "GCP_KEY"));
    }

    #[test]
    fn glob_suffix_star() {
        assert!(glob_match("*.amazonaws.com", "s3.us-east-1.amazonaws.com"));
        assert!(glob_match("*.amazonaws.com", "x.amazonaws.com"));
        assert!(!glob_match("*.amazonaws.com", "amazonaws.com.evil.com"));
        assert!(!glob_match("*.amazonaws.com", "evil.com"));
    }

    #[test]
    fn glob_middle_star() {
        assert!(glob_match("a*z", "abz"));
        assert!(glob_match("a*z", "az"));
        assert!(glob_match("a*z", "abcdz"));
        assert!(!glob_match("a*z", "abZ"));
    }

    #[test]
    fn glob_only_star_matches_anything() {
        assert!(glob_match("*", ""));
        assert!(glob_match("*", "anything"));
    }

    #[test]
    fn non_wildcard_prefix_length() {
        assert_eq!(non_wildcard_prefix_len("AWS_*"), 4);
        assert_eq!(non_wildcard_prefix_len("AWS_DEPLOY_KEY"), 14);
        assert_eq!(non_wildcard_prefix_len("*"), 0);
    }

    // ---- Defaults ------------------------------------------------------

    #[test]
    fn default_deny_when_empty_policy() {
        let mut e = PolicyEngine::from_str("").unwrap();
        let d = e.evaluate(&ctx("sign_request", Some("S")));
        assert_eq!(d.action, Action::Deny);
    }

    #[test]
    fn default_action_allow() {
        let toml = r#"
            [default]
            action = "allow"
        "#;
        let mut e = PolicyEngine::from_str(toml).unwrap();
        let d = e.evaluate(&ctx("sign_request", Some("S")));
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn missing_file_yields_default_deny() {
        let p = std::path::Path::new("/tmp/__cloak_nonexistent_policy_path__.toml");
        let mut e = PolicyEngine::from_path(p).unwrap();
        let d = e.evaluate(&ctx("sign_request", Some("S")));
        assert_eq!(d.action, Action::Deny);
    }

    // ---- Per-tool overrides --------------------------------------------

    #[test]
    fn per_tool_default_allow() {
        let toml = r#"
            [default]
            action = "deny"
            [tools.query_audit]
            allow = true
        "#;
        let mut e = PolicyEngine::from_str(toml).unwrap();
        assert_eq!(e.evaluate(&ctx("query_audit", None)).action, Action::Allow);
        assert_eq!(
            e.evaluate(&ctx("sign_request", Some("S"))).action,
            Action::Deny
        );
    }

    #[test]
    fn per_tool_default_deny_explicit() {
        let toml = r#"
            [default]
            action = "allow"
            [tools.sign_request]
            allow = false
        "#;
        let mut e = PolicyEngine::from_str(toml).unwrap();
        assert_eq!(
            e.evaluate(&ctx("sign_request", Some("S"))).action,
            Action::Deny
        );
    }

    // ---- Per-secret overrides ------------------------------------------

    #[test]
    fn secret_rule_overrides_tool_default() {
        let toml = r#"
            [default]
            action = "deny"
            [tools.sign_request]
            allow = false
            [[secrets]]
            name = "GITHUB_TOKEN"
            [secrets.tools.sign_request]
            allow = true
        "#;
        let mut e = PolicyEngine::from_str(toml).unwrap();
        let d = e.evaluate(&ctx("sign_request", Some("GITHUB_TOKEN")));
        assert_eq!(d.action, Action::Allow);
        assert!(d.matched_rule.unwrap().contains("GITHUB_TOKEN"));
    }

    #[test]
    fn secret_glob_matches() {
        let toml = r#"
            [default]
            action = "deny"
            [[secrets]]
            name = "AWS_*"
            [secrets.tools.sign_request]
            allow = true
        "#;
        let mut e = PolicyEngine::from_str(toml).unwrap();
        assert_eq!(
            e.evaluate(&ctx("sign_request", Some("AWS_DEPLOY_KEY")))
                .action,
            Action::Allow
        );
        assert_eq!(
            e.evaluate(&ctx("sign_request", Some("GCP_KEY"))).action,
            Action::Deny
        );
    }

    #[test]
    fn specific_rule_beats_glob() {
        let toml = r#"
            [default]
            action = "deny"
            [[secrets]]
            name = "AWS_*"
            [secrets.tools.sign_request]
            allow = true
            [[secrets]]
            name = "AWS_DEPLOY_KEY"
            [secrets.tools.sign_request]
            allow = false
        "#;
        let mut e = PolicyEngine::from_str(toml).unwrap();
        assert_eq!(
            e.evaluate(&ctx("sign_request", Some("AWS_DEPLOY_KEY")))
                .action,
            Action::Deny
        );
        assert_eq!(
            e.evaluate(&ctx("sign_request", Some("AWS_OTHER"))).action,
            Action::Allow
        );
    }

    // ---- proxy_http allowed_hosts --------------------------------------

    #[test]
    fn allowed_hosts_empty_list_denies() {
        let toml = r#"
            [default]
            action = "deny"
            [tools.proxy_authenticated_http_request]
            allowed_hosts = []
        "#;
        let mut e = PolicyEngine::from_str(toml).unwrap();
        let d = e.evaluate(&ctx_host(
            "proxy_authenticated_http_request",
            Some("S"),
            "api.github.com",
        ));
        assert_eq!(d.action, Action::Deny);
    }

    #[test]
    fn allowed_hosts_match_allows() {
        let toml = r#"
            [default]
            action = "deny"
            [[secrets]]
            name = "GITHUB_TOKEN"
            [secrets.tools.proxy_authenticated_http_request]
            allowed_hosts = ["api.github.com"]
        "#;
        let mut e = PolicyEngine::from_str(toml).unwrap();
        let allow = e.evaluate(&ctx_host(
            "proxy_authenticated_http_request",
            Some("GITHUB_TOKEN"),
            "api.github.com",
        ));
        assert_eq!(allow.action, Action::Allow);
        let deny = e.evaluate(&ctx_host(
            "proxy_authenticated_http_request",
            Some("GITHUB_TOKEN"),
            "evil.com",
        ));
        assert_eq!(deny.action, Action::Deny);
    }

    #[test]
    fn allowed_hosts_glob_subdomain() {
        let toml = r#"
            [default]
            action = "deny"
            [[secrets]]
            name = "AWS_KEY"
            [secrets.tools.proxy_authenticated_http_request]
            allowed_hosts = ["*.amazonaws.com"]
        "#;
        let mut e = PolicyEngine::from_str(toml).unwrap();
        let ok = e.evaluate(&ctx_host(
            "proxy_authenticated_http_request",
            Some("AWS_KEY"),
            "s3.us-east-1.amazonaws.com",
        ));
        assert_eq!(ok.action, Action::Allow);
        let evil = e.evaluate(&ctx_host(
            "proxy_authenticated_http_request",
            Some("AWS_KEY"),
            "amazonaws.com.evil.com",
        ));
        assert_eq!(evil.action, Action::Deny);
    }

    // ---- RequireConfirmation -------------------------------------------

    #[test]
    fn require_confirmation_returned() {
        let toml = r#"
            [default]
            action = "deny"
            [tools.mint_short_lived_token]
            require_confirmation = true
            confirmation_timeout_seconds = 30
        "#;
        let mut e = PolicyEngine::from_str(toml).unwrap();
        let d = e.evaluate(&ctx("mint_short_lived_token", Some("S")));
        assert_eq!(d.action, Action::RequireConfirmation);
    }

    #[test]
    fn require_confirmation_with_explicit_deny_still_denies() {
        let toml = r#"
            [default]
            action = "allow"
            [tools.mint_short_lived_token]
            require_confirmation = true
            allow = false
        "#;
        let mut e = PolicyEngine::from_str(toml).unwrap();
        let d = e.evaluate(&ctx("mint_short_lived_token", Some("S")));
        assert_eq!(d.action, Action::Deny);
    }

    // ---- Rate limiter --------------------------------------------------

    #[test]
    fn rate_limit_fires_after_burst() {
        let toml = r#"
            [default]
            action = "allow"
            [default.rate_limit]
            burst = 10
            refill_per_minute = 30
        "#;
        let mut e = PolicyEngine::from_str(toml).unwrap();
        let c = ctx("sign_request", Some("S"));
        for _ in 0..10 {
            assert!(e.check_rate(&c));
        }
        assert!(!e.check_rate(&c));
    }

    #[test]
    fn rate_limit_recovers_after_refill() {
        let toml = r#"
            [default]
            action = "allow"
            [default.rate_limit]
            burst = 2
            refill_per_minute = 6000
        "#; // 100/sec
        let mut e = PolicyEngine::from_str(toml).unwrap();
        let c = ctx("sign_request", Some("S"));
        assert!(e.check_rate(&c));
        assert!(e.check_rate(&c));
        assert!(!e.check_rate(&c));
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(e.check_rate(&c));
    }

    #[test]
    fn rate_limit_buckets_isolate_callers() {
        let toml = r#"
            [default]
            action = "allow"
            [default.rate_limit]
            burst = 1
            refill_per_minute = 1
        "#;
        let mut e = PolicyEngine::from_str(toml).unwrap();
        let mut a = ctx("sign_request", Some("S"));
        a.peer_basename = "alice";
        let mut b = ctx("sign_request", Some("S"));
        b.peer_basename = "bob";
        assert!(e.check_rate(&a));
        assert!(!e.check_rate(&a));
        // Different peer => different bucket.
        assert!(e.check_rate(&b));
    }

    #[test]
    fn rate_limit_buckets_split_by_secret() {
        let toml = r#"
            [default]
            action = "allow"
            [default.rate_limit]
            burst = 1
            refill_per_minute = 1
        "#;
        let mut e = PolicyEngine::from_str(toml).unwrap();
        let c1 = ctx("sign_request", Some("S1"));
        let c2 = ctx("sign_request", Some("S2"));
        assert!(e.check_rate(&c1));
        assert!(!e.check_rate(&c1));
        assert!(e.check_rate(&c2));
    }

    // ---- Matched-rule reporting ----------------------------------------

    #[test]
    fn matched_rule_path_for_secret_tool() {
        let toml = r#"
            [default]
            action = "deny"
            [[secrets]]
            name = "AWS_*"
            [secrets.tools.sign_request]
            allow = true
        "#;
        let mut e = PolicyEngine::from_str(toml).unwrap();
        let d = e.evaluate(&ctx("sign_request", Some("AWS_X")));
        assert_eq!(
            d.matched_rule.as_deref(),
            Some("[secrets.AWS_*].tools.sign_request")
        );
    }

    #[test]
    fn matched_rule_path_for_tool_only() {
        let toml = r#"
            [default]
            action = "deny"
            [tools.query_audit]
            allow = true
        "#;
        let mut e = PolicyEngine::from_str(toml).unwrap();
        let d = e.evaluate(&ctx("query_audit", None));
        assert_eq!(d.matched_rule.as_deref(), Some("[tools.query_audit]"));
    }

    #[test]
    fn no_matched_rule_for_default_path() {
        let mut e = PolicyEngine::from_str("[default]\naction = \"allow\"").unwrap();
        let d = e.evaluate(&ctx("sign_request", Some("S")));
        assert_eq!(d.action, Action::Allow);
        assert!(d.matched_rule.is_none());
    }

    // ---- Fallthrough behavior ------------------------------------------

    #[test]
    fn secret_rule_without_matching_tool_falls_to_tool_default() {
        let toml = r#"
            [default]
            action = "deny"
            [tools.query_audit]
            allow = true
            [[secrets]]
            name = "FOO"
            [secrets.tools.sign_request]
            allow = false
        "#;
        let mut e = PolicyEngine::from_str(toml).unwrap();
        // FOO matches the secret rule, but the rule has no entry for
        // query_audit — should fall through to [tools.query_audit].
        let d = e.evaluate(&ctx("query_audit", Some("FOO")));
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn unknown_tool_falls_to_default() {
        let toml = r#"
            [default]
            action = "deny"
        "#;
        let mut e = PolicyEngine::from_str(toml).unwrap();
        let d = e.evaluate(&ctx("totally_unknown_tool", Some("S")));
        assert_eq!(d.action, Action::Deny);
    }

    #[test]
    fn unknown_secret_falls_to_tool_default() {
        let toml = r#"
            [default]
            action = "deny"
            [tools.sign_request]
            allow = true
        "#;
        let mut e = PolicyEngine::from_str(toml).unwrap();
        let d = e.evaluate(&ctx("sign_request", Some("UNKNOWN")));
        assert_eq!(d.action, Action::Allow);
    }

    // ---- Default-policy file scenarios ---------------------------------

    fn default_engine() -> PolicyEngine {
        PolicyEngine::from_path(std::path::Path::new("../../scripts/policy.example.toml")).unwrap()
    }

    #[test]
    fn example_file_parses_and_query_audit_allowed() {
        let mut e = default_engine();
        assert_eq!(e.evaluate(&ctx("query_audit", None)).action, Action::Allow);
    }

    #[test]
    fn example_file_github_token_to_github_allowed() {
        let mut e = default_engine();
        let d = e.evaluate(&ctx_host(
            "proxy_authenticated_http_request",
            Some("GITHUB_TOKEN"),
            "api.github.com",
        ));
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn example_file_github_token_to_other_denied() {
        let mut e = default_engine();
        let d = e.evaluate(&ctx_host(
            "proxy_authenticated_http_request",
            Some("GITHUB_TOKEN"),
            "evil.com",
        ));
        assert_eq!(d.action, Action::Deny);
    }

    #[test]
    fn example_file_aws_glob_to_amazonaws_allowed() {
        let mut e = default_engine();
        let d = e.evaluate(&ctx_host(
            "proxy_authenticated_http_request",
            Some("AWS_DEPLOY_KEY"),
            "s3.us-east-1.amazonaws.com",
        ));
        assert_eq!(d.action, Action::Allow);
    }

    #[test]
    fn example_file_mint_requires_confirmation() {
        let mut e = default_engine();
        let d = e.evaluate(&ctx("mint_short_lived_token", Some("OPENAI_API_KEY")));
        assert_eq!(d.action, Action::RequireConfirmation);
    }

    #[test]
    fn example_file_unknown_tool_default_deny() {
        let mut e = default_engine();
        let d = e.evaluate(&ctx("nonexistent_tool", Some("FOO")));
        assert_eq!(d.action, Action::Deny);
    }

    #[test]
    fn example_file_proxy_no_secret_denied() {
        // proxy_http with no secret context falls to tool default with
        // allowed_hosts=[] → deny.
        let mut e = default_engine();
        let d = e.evaluate(&ctx_host(
            "proxy_authenticated_http_request",
            None,
            "api.github.com",
        ));
        assert_eq!(d.action, Action::Deny);
    }

    // ---- Misc ----------------------------------------------------------

    #[test]
    fn parse_invalid_toml_errors() {
        assert!(PolicyEngine::from_str("not = = toml").is_err());
    }

    #[test]
    fn proxy_http_no_target_with_allowlist_denies() {
        let toml = r#"
            [default]
            action = "deny"
            [[secrets]]
            name = "S"
            [secrets.tools.proxy_authenticated_http_request]
            allowed_hosts = ["api.example.com"]
        "#;
        let mut e = PolicyEngine::from_str(toml).unwrap();
        let c = EvalContext {
            tool: "proxy_authenticated_http_request",
            secret_name: Some("S"),
            secret_kind: None,
            target_host: None,
            peer_basename: "test",
        };
        assert_eq!(e.evaluate(&c).action, Action::Deny);
    }
}
