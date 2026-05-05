//! Method handlers for the privileged tool surface.
//!
//! These are the four MCP-callable methods (`tool.sign_request`,
//! `tool.proxy_http`, `tool.mint_token`, `tool.query_audit`) that turn
//! secrets into useful outbound work without ever returning the secret
//! itself.
//!
//! Every handler follows the same skeleton:
//! 1. Parse + validate params.
//! 2. Run the policy engine. On `Deny` (or `RequireConfirmation` in v0.1)
//!    audit a `Denied` entry and return `Error::PolicyDenied`.
//! 3. Check the rate limit. On exhaustion, audit `Denied` and return
//!    `Error::PolicyDenied("rate limited")`.
//! 4. Lock the vault mutex and `vault.show()` the secret (only after the
//!    policy gate has passed — a denied call must never even read the
//!    plaintext).
//! 5. Do the real work (sign / proxy / mint / query).
//! 6. Audit `Ok` (or `Error` if the real work failed after policy passed).
//! 7. Return only the *new* outputs — never echo the secret, never echo
//!    the auth header that was attached to a proxied request.
//!
//! AWS SigV4 signing (`tool.sign_request` with `scheme="aws-sigv4"`) and
//! AWS STS minting (`tool.mint_token` with `kind="aws-sts"`) are real, post
//! W1 (decision: option A). They use:
//! - `aws-sigv4` for the V4 algorithm — KAT-verified against the published
//!   AWS test suite (see `sigv4_kat_get_vanilla`).
//! - `aws-sdk-sts` (with the `rustls` / ring TLS feature) for STS calls;
//!   we deliberately avoid `aws-config` to keep aws-lc-rs out of the
//!   dependency graph (verified by `cargo tree -p cloak-core`).

use std::collections::BTreeMap;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::audit::{AuditDraft, AuditFilter, AuditLog, AuditResult, PeerSummary};
use crate::crypto::Secret;
use crate::egress::{header_map_from_btree, EgressClient, PreparedRequest};
use crate::error::{Error, Result};
use crate::policy::{Action, Decision, EvalContext, PolicyEngine};
use crate::vault::Vault;

// -------------------------------------------------------------------------
// HandlerCtx — the bag of references each handler call needs.
// -------------------------------------------------------------------------

/// Bundle of references threaded through every privileged tool handler.
///
/// Lifetime `'a` is the lifetime of the per-call borrow from the daemon's
/// long-lived `DaemonCtx`. The handlers must not retain anything from
/// `HandlerCtx` past the `await` they finish on.
pub struct HandlerCtx<'a> {
    /// The vault. `Mutex` because `rusqlite::Connection` is `!Sync`.
    pub vault: &'a Mutex<Vault>,
    /// The policy engine — its rate-limiter is mutable so we lock too.
    pub policy: &'a Mutex<PolicyEngine>,
    /// The hash-chained audit log.
    pub audit: &'a Mutex<AuditLog>,
    /// The shared outbound HTTP client.
    pub egress: &'a EgressClient,
    /// Pre-built peer summary (pid, basename, code-sig digest hex).
    pub peer: &'a PeerSummary,
}

// -------------------------------------------------------------------------
// Common helpers
// -------------------------------------------------------------------------

/// Map a public tool name (the IPC `tool.<x>` suffix) to its policy-engine
/// canonical name. The policy DSL uses the long-form `proxy_authenticated_http_request`
/// and `mint_short_lived_token`; the wire uses the abbreviated `proxy_http`
/// and `mint_token`. This helper centralizes the translation.
fn policy_tool_name(tool: &str) -> &'static str {
    match tool {
        "proxy_http" => "proxy_authenticated_http_request",
        "mint_token" => "mint_short_lived_token",
        "sign_request" => "sign_request",
        "query_audit" => "query_audit",
        _ => "unknown",
    }
}

/// Append a single audit entry, swallowing audit-write errors (logging
/// only). We never want a failed audit to mask the real outcome.
async fn audit_one(audit: &Mutex<AuditLog>, draft: AuditDraft) {
    let mut g = audit.lock().await;
    if let Err(e) = g.append(draft) {
        tracing::warn!(error = %e, "audit append failed");
    }
}

/// Parse a JSON `Value` as `T`, returning `Error::IpcFraming("invalid params")`
/// on any deserialization failure. Mirrors the daemon's `parse_params`.
fn parse_params<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T> {
    serde_json::from_value(v.clone()).map_err(|_| Error::IpcFraming("invalid params"))
}

/// Run the policy gate + rate-limit check for a tool call. On any deny,
/// audits a `Denied` entry and returns `Error::PolicyDenied(reason)`.
///
/// `secret_kind` is best-effort: we look it up via vault metadata if the
/// vault is unlocked; otherwise we pass `None` (denial would be the same
/// regardless, since we deny before reading the secret).
async fn enforce_policy(
    ctx: &HandlerCtx<'_>,
    tool_wire: &str,
    secret_name: Option<&str>,
    target_host: Option<&str>,
    target_for_audit: Option<String>,
) -> Result<()> {
    let policy_tool = policy_tool_name(tool_wire);

    // Resolve secret_kind without unlocking; we only inspect metadata.
    let secret_kind: Option<String> = if let Some(name) = secret_name {
        let v = ctx.vault.lock().await;
        match v.get_metadata(name) {
            Ok(md) => Some(md.kind.as_str().to_string()),
            Err(_) => None,
        }
    } else {
        None
    };

    let eval_ctx = EvalContext {
        tool: policy_tool,
        secret_name,
        secret_kind: secret_kind.as_deref(),
        target_host,
        peer_basename: ctx.peer.basename.as_str(),
    };

    // Lock the policy engine for both decision and rate-bucket update.
    let mut engine = ctx.policy.lock().await;
    let decision: Decision = engine.evaluate(&eval_ctx);

    let deny_reason: Option<String> = match decision.action {
        Action::Allow => None,
        Action::Deny => Some(format!("denied: {}", decision.reason)),
        Action::RequireConfirmation => Some(format!(
            "confirmation not implemented for {} in v0.1",
            tool_wire
        )),
    };

    if let Some(reason) = deny_reason {
        drop(engine);
        audit_one(
            ctx.audit,
            AuditDraft {
                peer: ctx.peer.clone(),
                tool: format!("tool.{tool_wire}"),
                secret: secret_name.map(str::to_string),
                target: target_for_audit.clone(),
                result: AuditResult::Denied,
                note: Some(reason.clone()),
            },
        )
        .await;
        return Err(Error::PolicyDenied(reason));
    }

    // Rate limit (a separate bucket per tool/peer/secret).
    if !engine.check_rate(&eval_ctx) {
        drop(engine);
        audit_one(
            ctx.audit,
            AuditDraft {
                peer: ctx.peer.clone(),
                tool: format!("tool.{tool_wire}"),
                secret: secret_name.map(str::to_string),
                target: target_for_audit,
                result: AuditResult::Denied,
                note: Some("rate limited".to_string()),
            },
        )
        .await;
        return Err(Error::PolicyDenied("rate limited".to_string()));
    }
    Ok(())
}

// -------------------------------------------------------------------------
// tool.sign_request
// -------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct SignRequestParams {
    secret_name: String,
    /// `"hmac-sha256"` or `"aws-sigv4"`.
    scheme: String,
    method: String,
    url: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body_b64: Option<String>,
    /// Optional: AWS SigV4 region (defaults to `us-east-1`).
    #[serde(default)]
    aws_region: Option<String>,
    /// Optional: AWS SigV4 service (defaults to `execute-api`).
    #[serde(default)]
    aws_service: Option<String>,
}

/// Handler for `tool.sign_request`.
///
/// Returns only the new/modified auth headers — never the original
/// request headers, never the body, never the secret.
///
/// HMAC-SHA256 canonical string (documented):
/// ```text
/// {METHOD}\n{URL}\n{sha256_hex(body || b"")}\n
/// ```
/// The signature is `HMAC-SHA256(key, canonical_string)` and is returned
/// as `X-Cloak-Signature: <lowercase hex>`.
///
/// AWS SigV4 (v0.1 stub): see `sign_aws_sigv4_stub`. The secret value
/// must be in the form `<access_key_id>:<secret_access_key>`.
pub async fn sign_request(ctx: &HandlerCtx<'_>, params: &Value) -> Result<Value> {
    let p: SignRequestParams = parse_params(params)?;

    // Parse URL early so we can pass the host into policy. A bad URL is
    // a client error and is reported before the policy check (still no
    // secret access yet, so no audit bypass).
    let url = url::Url::parse(&p.url).map_err(|_| Error::IpcFraming("invalid url"))?;
    let host = url.host_str().map(str::to_string);

    enforce_policy(
        ctx,
        "sign_request",
        Some(&p.secret_name),
        host.as_deref(),
        host.clone(),
    )
    .await?;

    // Vault must be unlocked to read the secret.
    let secret_value: Secret<String> = {
        let v = ctx.vault.lock().await;
        if !v.is_unlocked() {
            return Err(Error::Other("vault locked"));
        }
        v.show(&p.secret_name)?
    };

    // Decode the body once so both schemes can hash it.
    let body_bytes: Vec<u8> = match &p.body_b64 {
        Some(s) => base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|_| Error::IpcFraming("invalid body_b64"))?,
        None => Vec::new(),
    };

    let scheme_label;
    let new_headers: BTreeMap<String, String> = match p.scheme.as_str() {
        "hmac-sha256" => {
            scheme_label = "scheme=hmac-sha256";
            sign_hmac_sha256(&p.method, &p.url, &body_bytes, secret_value.expose_secret())?
        }
        "aws-sigv4" => {
            scheme_label = "scheme=aws-sigv4";
            let region = p.aws_region.as_deref().unwrap_or("us-east-1");
            let service = p.aws_service.as_deref().unwrap_or("execute-api");
            sign_aws_sigv4(
                &p.method,
                &url,
                &p.headers,
                &body_bytes,
                secret_value.expose_secret(),
                region,
                service,
                Utc::now(),
            )
            .map_err(|e| {
                // Constant message — never surface key material or AWS internals.
                tracing::debug!(error = %e, "aws-sigv4 sign failed");
                Error::Other("aws-sigv4: sign failed")
            })?
        }
        other => {
            audit_one(
                ctx.audit,
                AuditDraft {
                    peer: ctx.peer.clone(),
                    tool: "tool.sign_request".to_string(),
                    secret: Some(p.secret_name.clone()),
                    target: host,
                    result: AuditResult::Error,
                    note: Some(format!("unknown scheme: {other}")),
                },
            )
            .await;
            return Err(Error::IpcFraming("unknown sign_request scheme"));
        }
    };

    audit_one(
        ctx.audit,
        AuditDraft {
            peer: ctx.peer.clone(),
            tool: "tool.sign_request".to_string(),
            secret: Some(p.secret_name.clone()),
            target: host,
            result: AuditResult::Ok,
            note: Some(scheme_label.to_string()),
        },
    )
    .await;

    Ok(json!({ "headers": new_headers }))
}

/// Compute the HMAC-SHA256 signature header for a `(method, url, body)`
/// triple using `key`. Returns just `{"X-Cloak-Signature": "<hex>"}`.
fn sign_hmac_sha256(
    method: &str,
    url: &str,
    body: &[u8],
    key: &str,
) -> Result<BTreeMap<String, String>> {
    let body_sha = {
        let mut h = Sha256::new();
        h.update(body);
        hex::encode(h.finalize())
    };
    let canonical = format!("{}\n{}\n{}\n", method.to_ascii_uppercase(), url, body_sha);

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .map_err(|_| Error::Other("sign_request: hmac key init failed"))?;
    mac.update(canonical.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());

    let mut out = BTreeMap::new();
    out.insert("X-Cloak-Signature".to_string(), sig);
    Ok(out)
}

/// Compute AWS SigV4 signature headers for a `(method, url, headers, body)`
/// tuple. Returns only the headers SigV4 added or changed:
/// `Authorization`, `X-Amz-Date`, `X-Amz-Content-Sha256`, and `Host` (if
/// the caller didn't already supply one).
///
/// `key_pair` must be `"<access_key_id>:<secret_access_key>"`. On any
/// other shape, returns `Error::Other` with a constant message — the
/// secret value is never embedded in the error.
///
/// `now` is parameterized so the KAT vectors can pin the timestamp.
#[allow(clippy::too_many_arguments)]
fn sign_aws_sigv4(
    method: &str,
    url: &url::Url,
    request_headers: &BTreeMap<String, String>,
    body: &[u8],
    key_pair: &str,
    region: &str,
    service: &str,
    now: DateTime<Utc>,
) -> Result<BTreeMap<String, String>> {
    use aws_credential_types::Credentials;
    use aws_sigv4::http_request::{
        sign, SignableBody, SignableRequest, SignatureLocation, SigningSettings,
    };
    use aws_sigv4::sign::v4;
    use std::time::SystemTime;

    // Parse "<access_key_id>:<secret_access_key>".
    let (access_key_id, secret_access_key) = match key_pair.split_once(':') {
        Some((a, b)) if !a.is_empty() && !b.is_empty() => (a, b),
        _ => {
            return Err(Error::Other("aws-sigv4: secret must be 'AKID:SECRET'"));
        }
    };

    // Build the headers we want to feed into the canonicalization. SigV4
    // requires the Host header — supply one if the caller didn't.
    // Keep the caller's keys verbatim (case-insensitive matching is the
    // signing layer's job).
    let mut headers: Vec<(String, String)> = Vec::with_capacity(request_headers.len() + 1);
    let caller_has_host = request_headers
        .keys()
        .any(|k| k.eq_ignore_ascii_case("host"));
    let host_str = url.host_str().unwrap_or("").to_string();
    if !caller_has_host {
        headers.push(("host".to_string(), host_str.clone()));
    }
    for (k, v) in request_headers.iter() {
        headers.push((k.clone(), v.clone()));
    }

    let identity = Credentials::from_keys(access_key_id, secret_access_key, None).into();
    let mut settings = SigningSettings::default();
    settings.signature_location = SignatureLocation::Headers;
    let signing_params: aws_sigv4::http_request::SigningParams = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name(service)
        .time(SystemTime::from(now))
        .settings(settings)
        .build()
        .map_err(|_| Error::Other("aws-sigv4: signing params build failed"))?
        .into();

    // Build the signable request. We can't pass `&BTreeMap` directly; use a
    // borrowed iterator of (name, value) tuples, which is what the API
    // expects.
    let header_iter = headers.iter().map(|(k, v)| (k.as_str(), v.as_str()));
    let signable =
        SignableRequest::new(method, url.as_str(), header_iter, SignableBody::Bytes(body))
            .map_err(|_| Error::Other("aws-sigv4: signable request build failed"))?;

    let signing_output =
        sign(signable, &signing_params).map_err(|_| Error::Other("aws-sigv4: sign failed"))?;
    let (instructions, _signature) = signing_output.into_parts();

    let body_sha256_hex = {
        let mut h = Sha256::new();
        h.update(body);
        hex::encode(h.finalize())
    };

    let mut out: BTreeMap<String, String> = BTreeMap::new();
    // The instructions contain the headers SigV4 wants applied. We map
    // them into our return shape (sorted, deduped, canonical-cased).
    for (name, value) in instructions.headers() {
        // Canonicalize a few well-known names to their conventional case
        // for ergonomic interop with HTTP libraries.
        let canon = match name.to_ascii_lowercase().as_str() {
            "authorization" => "Authorization",
            "x-amz-date" => "X-Amz-Date",
            "x-amz-content-sha256" => "X-Amz-Content-Sha256",
            "x-amz-security-token" => "X-Amz-Security-Token",
            "host" => "Host",
            _ => name,
        };
        out.insert(canon.to_string(), value.to_string());
    }
    // If the signer didn't surface X-Amz-Content-Sha256 (it does for some
    // services, e.g. s3, but not all), include it ourselves — callers
    // expect a stable shape.
    out.entry("X-Amz-Content-Sha256".to_string())
        .or_insert(body_sha256_hex);
    if !caller_has_host {
        out.entry("Host".to_string()).or_insert(host_str);
    }
    Ok(out)
}

// -------------------------------------------------------------------------
// tool.proxy_http
// -------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ProxyHttpParams {
    secret_name: String,
    method: String,
    url: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body_b64: Option<String>,
    /// `"bearer"` | `"basic"` | `"header"` | `"query"`.
    auth_scheme: String,
    #[serde(default)]
    header_name: Option<String>,
    #[serde(default)]
    query_name: Option<String>,
}

/// Handler for `tool.proxy_http`.
///
/// Never echoes the auth header it attaches; never returns the secret.
/// Strips `Authorization`, `Cookie`, and `X-Api-Key` from caller-supplied
/// headers so a model cannot smuggle its own auth through this tool.
pub async fn proxy_http(ctx: &HandlerCtx<'_>, params: &Value) -> Result<Value> {
    let p: ProxyHttpParams = parse_params(params)?;

    let mut url = url::Url::parse(&p.url).map_err(|_| Error::IpcFraming("invalid url"))?;
    let host = url.host_str().map(str::to_string);

    enforce_policy(
        ctx,
        "proxy_http",
        Some(&p.secret_name),
        host.as_deref(),
        host.clone(),
    )
    .await?;

    let secret_value: Secret<String> = {
        let v = ctx.vault.lock().await;
        if !v.is_unlocked() {
            return Err(Error::Other("vault locked"));
        }
        v.show(&p.secret_name)?
    };

    // Strip caller-supplied auth-bearing headers — case-insensitive.
    let stripped: BTreeMap<String, String> = p
        .headers
        .iter()
        .filter(|(k, _)| {
            let lk = k.to_ascii_lowercase();
            lk != "authorization" && lk != "cookie" && lk != "x-api-key"
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    // Build the base header map, then attach auth based on scheme.
    let mut headers = header_map_from_btree(&stripped)?;
    let secret_str = secret_value.expose_secret();

    match p.auth_scheme.as_str() {
        "bearer" => {
            let val = format!("Bearer {secret_str}");
            let v = reqwest::header::HeaderValue::from_str(&val)
                .map_err(|_| Error::Other("proxy_http: invalid bearer token"))?;
            headers.insert(reqwest::header::AUTHORIZATION, v);
        }
        "basic" => {
            // v0.1: secret must already be `user:pass`.
            if !secret_str.contains(':') {
                return Err(Error::Other(
                    "proxy_http: basic auth secret must be \"user:pass\"",
                ));
            }
            let encoded = base64::engine::general_purpose::STANDARD.encode(secret_str.as_bytes());
            let val = format!("Basic {encoded}");
            let v = reqwest::header::HeaderValue::from_str(&val)
                .map_err(|_| Error::Other("proxy_http: invalid basic token"))?;
            headers.insert(reqwest::header::AUTHORIZATION, v);
        }
        "header" => {
            let name = p
                .header_name
                .as_deref()
                .ok_or(Error::IpcFraming("proxy_http: header_name required"))?;
            let hn = reqwest::header::HeaderName::try_from(name.to_ascii_lowercase().as_bytes())
                .map_err(|_| Error::Other("proxy_http: invalid header name"))?;
            let hv = reqwest::header::HeaderValue::from_str(secret_str)
                .map_err(|_| Error::Other("proxy_http: invalid header value"))?;
            headers.insert(hn, hv);
        }
        "query" => {
            let name = p
                .query_name
                .as_deref()
                .ok_or(Error::IpcFraming("proxy_http: query_name required"))?;
            url.query_pairs_mut().append_pair(name, secret_str);
        }
        _ => {
            return Err(Error::IpcFraming("proxy_http: unknown auth_scheme"));
        }
    }

    // Build the request body.
    let body_bytes: Option<Vec<u8>> = match &p.body_b64 {
        Some(s) => Some(
            base64::engine::general_purpose::STANDARD
                .decode(s)
                .map_err(|_| Error::IpcFraming("invalid body_b64"))?,
        ),
        None => None,
    };

    let method = reqwest::Method::from_bytes(p.method.to_ascii_uppercase().as_bytes())
        .map_err(|_| Error::IpcFraming("invalid http method"))?;

    let prepared = PreparedRequest {
        method,
        url,
        headers,
        body: body_bytes,
    };

    let resp = match ctx.egress.execute(prepared).await {
        Ok(r) => r,
        Err(e) => {
            audit_one(
                ctx.audit,
                AuditDraft {
                    peer: ctx.peer.clone(),
                    tool: "tool.proxy_http".to_string(),
                    secret: Some(p.secret_name.clone()),
                    target: host.clone(),
                    result: AuditResult::Error,
                    note: Some(format!("egress error: {e}")),
                },
            )
            .await;
            return Err(e);
        }
    };

    audit_one(
        ctx.audit,
        AuditDraft {
            peer: ctx.peer.clone(),
            tool: "tool.proxy_http".to_string(),
            secret: Some(p.secret_name.clone()),
            target: host,
            result: AuditResult::Ok,
            note: Some(format!("status={}", resp.status)),
        },
    )
    .await;

    let body_b64 = base64::engine::general_purpose::STANDARD.encode(&resp.body);
    // Header keys are already lowercased by `egress::execute`.
    Ok(json!({
        "status": resp.status,
        "headers": resp.headers,
        "body_b64": body_b64,
    }))
}

// -------------------------------------------------------------------------
// tool.mint_token
// -------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct MintTokenParams {
    secret_name: String,
    /// `"aws-sts"` | `"github-app"` | `"gitlab-pat"`.
    kind: String,
    #[serde(default)]
    #[allow(dead_code)]
    scope: Value,
    #[serde(default)]
    ttl_seconds: Option<u32>,
}

/// AWS-side bounds for `GetSessionToken` duration. The lower bound is the
/// API's documented minimum (15 min), the upper bound is the documented
/// maximum (36 h). We clamp at the edges and audit a `note` when we do.
const AWS_STS_MIN_TTL_SECONDS: i64 = 900;
const AWS_STS_MAX_TTL_SECONDS: i64 = 129_600;

/// Optional STS client factory injected by tests (cfg(test) only) so they
/// can hand the handler a mocked client without going through the real
/// configuration path. Production builds (cfg(not(test))) always use
/// [`build_real_sts_client`].
#[cfg(any(test, feature = "test-util"))]
pub type StsClientFactory =
    std::sync::Arc<dyn Fn(&str, &str, &str) -> aws_sdk_sts::Client + Send + Sync>;

#[cfg(any(test, feature = "test-util"))]
static AWS_STS_TEST_FACTORY: once_cell::sync::OnceCell<std::sync::Mutex<Option<StsClientFactory>>> =
    once_cell::sync::OnceCell::new();

/// Install (or remove) a test-only STS client factory. Returns the
/// previously installed factory, if any. Only available in `cfg(test)`
/// or with the `test-util` feature.
#[cfg(any(test, feature = "test-util"))]
pub fn set_test_sts_factory(f: Option<StsClientFactory>) -> Option<StsClientFactory> {
    let cell = AWS_STS_TEST_FACTORY.get_or_init(|| std::sync::Mutex::new(None));
    let mut g = cell.lock().expect("test factory lock");
    std::mem::replace(&mut *g, f)
}

#[cfg(any(test, feature = "test-util"))]
fn current_test_sts_factory() -> Option<StsClientFactory> {
    let cell = AWS_STS_TEST_FACTORY.get_or_init(|| std::sync::Mutex::new(None));
    cell.lock().ok().and_then(|g| g.clone())
}

#[cfg(not(any(test, feature = "test-util")))]
fn current_test_sts_factory() -> Option<fn(&str, &str, &str) -> aws_sdk_sts::Client> {
    None
}

/// Build a real STS client from static credentials and a region. We
/// deliberately avoid `aws-config` so the dependency graph stays free of
/// `aws-lc-rs` (verified by `cargo tree -p cloak-core`).
fn build_real_sts_client(akid: &str, secret: &str, region: &str) -> aws_sdk_sts::Client {
    use aws_credential_types::Credentials;
    use aws_sdk_sts::config::{BehaviorVersion, Region};

    let creds = Credentials::from_keys(akid, secret, None);
    let conf = aws_sdk_sts::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(region.to_string()))
        .credentials_provider(creds)
        .build();
    aws_sdk_sts::Client::from_conf(conf)
}

/// Handler for `tool.mint_token`.
///
/// `aws-sts` is implemented as a real `GetSessionToken` call against the
/// AWS STS API. `github-app` and `gitlab-pat` return
/// `Error::Other("mint_token: kind not supported in v0.1")` after passing
/// policy + rate limit (still audited as `Error`).
pub async fn mint_token(ctx: &HandlerCtx<'_>, params: &Value) -> Result<Value> {
    let p: MintTokenParams = parse_params(params)?;

    enforce_policy(ctx, "mint_token", Some(&p.secret_name), None, None).await?;

    let secret_value: Secret<String> = {
        let v = ctx.vault.lock().await;
        if !v.is_unlocked() {
            return Err(Error::Other("vault locked"));
        }
        v.show(&p.secret_name)?
    };

    let requested_ttl = p
        .ttl_seconds
        .map(|t| t as i64)
        .unwrap_or(AWS_STS_MIN_TTL_SECONDS);
    let mut clamped_note: Option<&'static str> = None;
    let ttl = if requested_ttl < AWS_STS_MIN_TTL_SECONDS {
        clamped_note = Some(" clamped=min");
        AWS_STS_MIN_TTL_SECONDS
    } else if requested_ttl > AWS_STS_MAX_TTL_SECONDS {
        clamped_note = Some(" clamped=max");
        AWS_STS_MAX_TTL_SECONDS
    } else {
        requested_ttl
    };

    match p.kind.as_str() {
        "aws-sts" => {
            // Parse "<access_key_id>:<secret_access_key>".
            let key_pair = secret_value.expose_secret();
            let (akid, secret_key) = match key_pair.split_once(':') {
                Some((a, b)) if !a.is_empty() && !b.is_empty() => (a, b),
                _ => {
                    audit_one(
                        ctx.audit,
                        AuditDraft {
                            peer: ctx.peer.clone(),
                            tool: "tool.mint_token".to_string(),
                            secret: Some(p.secret_name.clone()),
                            target: None,
                            result: AuditResult::Error,
                            note: Some("kind=aws-sts secret-shape-invalid".to_string()),
                        },
                    )
                    .await;
                    return Err(Error::Other("aws-sts: secret must be 'AKID:SECRET'"));
                }
            };

            // Region: from params.scope.region if present, else default.
            let region: String = match &p.scope {
                Value::Object(map) => match map.get("region").and_then(Value::as_str) {
                    Some(r) if !r.is_empty() => r.to_string(),
                    _ => "us-east-1".to_string(),
                },
                _ => "us-east-1".to_string(),
            };

            let client = match current_test_sts_factory() {
                Some(factory) => (factory)(akid, secret_key, &region),
                None => build_real_sts_client(akid, secret_key, &region),
            };

            // Call STS GetSessionToken. On any AWS error, audit + return
            // a constant-message error.
            let resp = match client
                .get_session_token()
                .duration_seconds(ttl as i32)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(error = %e, "GetSessionToken failed");
                    audit_one(
                        ctx.audit,
                        AuditDraft {
                            peer: ctx.peer.clone(),
                            tool: "tool.mint_token".to_string(),
                            secret: Some(p.secret_name.clone()),
                            target: None,
                            result: AuditResult::Error,
                            note: Some(format!(
                                "kind=aws-sts ttl={ttl}s region={region} api-error"
                            )),
                        },
                    )
                    .await;
                    return Err(Error::Other("aws-sts: GetSessionToken failed"));
                }
            };

            let creds = match resp.credentials() {
                Some(c) => c,
                None => {
                    audit_one(
                        ctx.audit,
                        AuditDraft {
                            peer: ctx.peer.clone(),
                            tool: "tool.mint_token".to_string(),
                            secret: Some(p.secret_name.clone()),
                            target: None,
                            result: AuditResult::Error,
                            note: Some(format!(
                                "kind=aws-sts ttl={ttl}s region={region} empty-credentials"
                            )),
                        },
                    )
                    .await;
                    return Err(Error::Other(
                        "aws-sts: GetSessionToken returned no credentials",
                    ));
                }
            };

            let expiration_secs = creds.expiration().secs();
            let expiration_dt: DateTime<Utc> =
                DateTime::<Utc>::from_timestamp(expiration_secs, 0).unwrap_or_else(Utc::now);

            // Encode the temporary credentials as a base64'd JSON envelope
            // — this is the documented "token" wire shape.
            let envelope = json!({
                "access_key_id": creds.access_key_id(),
                "secret_access_key": creds.secret_access_key(),
                "session_token": creds.session_token(),
                "expiration": expiration_dt.to_rfc3339(),
            });
            let envelope_bytes = serde_json::to_vec(&envelope)
                .map_err(|_| Error::Other("aws-sts: envelope encoding failed"))?;
            let token = base64::engine::general_purpose::STANDARD.encode(envelope_bytes);

            audit_one(
                ctx.audit,
                AuditDraft {
                    peer: ctx.peer.clone(),
                    tool: "tool.mint_token".to_string(),
                    secret: Some(p.secret_name.clone()),
                    target: None,
                    result: AuditResult::Ok,
                    note: Some(format!(
                        "kind=aws-sts ttl={ttl}s region={region}{}",
                        clamped_note.unwrap_or("")
                    )),
                },
            )
            .await;

            Ok(json!({
                "token": token,
                "expires_at": expiration_dt.to_rfc3339(),
            }))
        }
        other => {
            audit_one(
                ctx.audit,
                AuditDraft {
                    peer: ctx.peer.clone(),
                    tool: "tool.mint_token".to_string(),
                    secret: Some(p.secret_name.clone()),
                    target: None,
                    result: AuditResult::Error,
                    note: Some(format!("kind={other} unsupported")),
                },
            )
            .await;
            Err(Error::Other("mint_token: kind not supported in v0.1"))
        }
    }
}

// -------------------------------------------------------------------------
// tool.query_audit
// -------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct QueryAuditParams {
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    until: Option<String>,
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    secret: Option<String>,
    /// `"ok"` | `"denied"` | `"error"`.
    #[serde(default)]
    result: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

/// Handler for `tool.query_audit`. Returns audit entries matching the
/// filter; entries already exclude any plaintext secret material.
pub async fn query_audit(ctx: &HandlerCtx<'_>, params: &Value) -> Result<Value> {
    let p: QueryAuditParams = parse_params(params)?;

    enforce_policy(ctx, "query_audit", None, None, None).await?;

    let parse_ts = |s: &str| -> Result<DateTime<Utc>> {
        DateTime::parse_from_rfc3339(s)
            .map(|d| d.with_timezone(&Utc))
            .map_err(|_| Error::IpcFraming("invalid rfc3339 timestamp"))
    };

    let result_kind = match p.result.as_deref() {
        None => None,
        Some("ok") => Some(AuditResult::Ok),
        Some("denied") => Some(AuditResult::Denied),
        Some("error") => Some(AuditResult::Error),
        Some(_) => return Err(Error::IpcFraming("query_audit: unknown result filter")),
    };

    let filter = AuditFilter {
        since: p.since.as_deref().map(parse_ts).transpose()?,
        until: p.until.as_deref().map(parse_ts).transpose()?,
        tool: p.tool,
        secret: p.secret,
        result: result_kind,
        limit: p.limit.unwrap_or(0),
    };

    let entries = {
        let g = ctx.audit.lock().await;
        g.query(&filter)?
    };

    // Audit *this* call too. We do this AFTER the read so the count we
    // log doesn't include the entry we're about to add.
    let n = entries.len();
    audit_one(
        ctx.audit,
        AuditDraft {
            peer: ctx.peer.clone(),
            tool: "tool.query_audit".to_string(),
            secret: None,
            target: None,
            result: AuditResult::Ok,
            note: Some(format!("returned {n} entries")),
        },
    )
    .await;

    let entries_json: Vec<Value> = entries
        .into_iter()
        .map(|e| serde_json::to_value(e).unwrap_or(Value::Null))
        .collect();

    Ok(json!({ "entries": entries_json }))
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_canonical_string_format() {
        // The HMAC must match a hand-computed value over the documented
        // canonical string.
        let key = "sekret";
        let method = "GET";
        let url = "https://example.com/foo";
        let body: &[u8] = b"";
        let body_sha = {
            let mut h = Sha256::new();
            h.update(body);
            hex::encode(h.finalize())
        };
        let canonical = format!("{method}\n{url}\n{body_sha}\n");

        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
        mac.update(canonical.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());

        let h = sign_hmac_sha256(method, url, body, key).unwrap();
        assert_eq!(h.get("X-Cloak-Signature").unwrap(), &expected);
    }

    #[test]
    fn hmac_different_body_yields_different_sig() {
        let a = sign_hmac_sha256("POST", "https://x/y", b"hello", "k").unwrap();
        let b = sign_hmac_sha256("POST", "https://x/y", b"world", "k").unwrap();
        assert_ne!(
            a.get("X-Cloak-Signature").unwrap(),
            b.get("X-Cloak-Signature").unwrap()
        );
    }

    #[test]
    fn sigv4_rejects_bad_key_format() {
        let url = url::Url::parse("https://example.com/foo").unwrap();
        let r = sign_aws_sigv4(
            "GET",
            &url,
            &BTreeMap::new(),
            b"",
            "no-colon-here",
            "us-east-1",
            "execute-api",
            Utc::now(),
        );
        assert!(r.is_err());
    }

    #[test]
    fn sigv4_emits_expected_header_set() {
        let url = url::Url::parse("https://example.com/foo?bar=baz").unwrap();
        let h = sign_aws_sigv4(
            "GET",
            &url,
            &BTreeMap::new(),
            b"",
            "AKIA1234567890:secretsecret",
            "us-east-1",
            "execute-api",
            Utc::now(),
        )
        .unwrap();
        assert!(h.contains_key("Authorization"));
        assert!(h.contains_key("X-Amz-Date"));
        assert!(h.contains_key("X-Amz-Content-Sha256"));
        assert!(h.contains_key("Host"));
        // No stub marker — this is real V4.
        assert!(!h.contains_key("X-Cloak-Sigv4-Stub"));
        assert_eq!(h.get("Host").map(String::as_str), Some("example.com"));
        assert!(h
            .get("Authorization")
            .unwrap()
            .starts_with("AWS4-HMAC-SHA256 Credential=AKIA1234567890/"));
    }

    /// AWS published SigV4 KAT: `get-vanilla` from the AWS Signature Version 4
    /// Test Suite. Source:
    /// <https://github.com/saibotsivad/aws-sig-v4-test-suite/tree/master/raw/aws-sig-v4-test-suite/get-vanilla>
    /// (a verbatim mirror of the original `aws4_testsuite.zip` that AWS once
    /// shipped at <https://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html>).
    /// Credentials are the published example keys
    /// `AKIDEXAMPLE / wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY` over region
    /// `us-east-1`, service `service`, at `20150830T123600Z`.
    #[test]
    fn sigv4_kat_get_vanilla() {
        // Pin the timestamp to 2015-08-30T12:36:00Z to match the KAT.
        let when: DateTime<Utc> = DateTime::parse_from_rfc3339("2015-08-30T12:36:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let url = url::Url::parse("https://example.amazonaws.com/").unwrap();
        let key_pair = "AKIDEXAMPLE:wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

        let h = sign_aws_sigv4(
            "GET",
            &url,
            &BTreeMap::new(),
            b"",
            key_pair,
            "us-east-1",
            "service",
            when,
        )
        .expect("sign get-vanilla");

        let expected = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31";
        assert_eq!(
            h.get("Authorization").map(String::as_str),
            Some(expected),
            "get-vanilla Authorization mismatch"
        );
        assert_eq!(
            h.get("X-Amz-Date").map(String::as_str),
            Some("20150830T123600Z")
        );
    }

    #[test]
    fn policy_tool_name_translation() {
        assert_eq!(
            policy_tool_name("proxy_http"),
            "proxy_authenticated_http_request"
        );
        assert_eq!(policy_tool_name("mint_token"), "mint_short_lived_token");
        assert_eq!(policy_tool_name("sign_request"), "sign_request");
        assert_eq!(policy_tool_name("query_audit"), "query_audit");
        assert_eq!(policy_tool_name("nope"), "unknown");
    }
}
