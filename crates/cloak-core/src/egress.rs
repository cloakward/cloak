//! Outbound HTTP — the *only* place outbound HTTP lives in the workspace.
//!
//! `cloak-mcp` MUST NOT import any HTTP client. Every privileged tool that
//! needs to talk to the network goes through this module.
//!
//! Build a single `EgressClient` at daemon start and reuse it. The client
//! is configured with:
//! - rustls TLS (no native-tls / OpenSSL),
//! - a hard limit of 3 redirects,
//! - a 30-second total timeout per request.
//!
//! Transport failures are surfaced as `Error::Other("egress: ...")` —
//! short, static-ish strings; they never carry secret material.
//!
//! Defense-in-depth note: this module does NOT perform any policy or
//! allowlist checks. Those live in `handlers::proxy_http` and run **before**
//! the request is built. Egress is only the I/O.

use std::collections::BTreeMap;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use url::Url;

use crate::error::{Error, Result};

/// Wrapper around a long-lived `reqwest::Client` configured for cloak's
/// outbound calls. Build once at daemon startup; clone is cheap.
#[derive(Clone)]
pub struct EgressClient {
    inner: reqwest::Client,
}

impl EgressClient {
    /// Construct a fresh client with rustls TLS, a 3-redirect cap, and a
    /// 30-second per-request timeout. Returns `Error::Other` (never panics)
    /// if the underlying builder fails.
    pub fn new() -> Result<Self> {
        let inner = reqwest::Client::builder()
            .use_rustls_tls()
            .redirect(reqwest::redirect::Policy::limited(3))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| Error::Other("egress: failed to build http client"))?;
        Ok(Self { inner })
    }

    /// Execute a fully-formed `PreparedRequest` and collect the response
    /// into a `RawResponse` (status + lowercased-key headers + bytes body).
    ///
    /// Errors:
    /// - DNS / connect / TLS / read errors → `Error::Other("egress: ...")`.
    /// - HTTP 4xx/5xx are *not* errors here — the caller decides what to
    ///   do with the status code.
    pub async fn execute(&self, req: PreparedRequest) -> Result<RawResponse> {
        let mut builder = self
            .inner
            .request(req.method.clone(), req.url.clone())
            .headers(req.headers.clone());
        if let Some(body) = req.body {
            builder = builder.body(body);
        }
        let resp = builder
            .send()
            .await
            .map_err(|_| Error::Other("egress: request failed"))?;

        let status = resp.status().as_u16();
        let mut headers: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in resp.headers().iter() {
            // Lowercase, owned key. Skip non-utf8 values (rare; reqwest
            // will already have rejected most bad bytes upstream).
            if let Ok(s) = v.to_str() {
                headers.insert(k.as_str().to_ascii_lowercase(), s.to_string());
            }
        }
        let body = resp
            .bytes()
            .await
            .map_err(|_| Error::Other("egress: body read failed"))?
            .to_vec();
        Ok(RawResponse {
            status,
            headers,
            body,
        })
    }
}

/// A request that has already been built (URL parsed, headers set, body
/// optionally attached). Constructed by handlers, executed by egress.
#[derive(Debug, Clone)]
pub struct PreparedRequest {
    /// HTTP method (`GET`, `POST`, ...).
    pub method: reqwest::Method,
    /// Fully-parsed URL (including scheme + host + path + query).
    pub url: Url,
    /// Header map (already includes any auth header attached by the handler).
    pub headers: HeaderMap,
    /// Optional request body bytes.
    pub body: Option<Vec<u8>>,
}

/// A captured HTTP response — status, lowercase-keyed sorted header map,
/// and raw body bytes.
#[derive(Debug, Clone)]
pub struct RawResponse {
    /// HTTP status code (e.g. `200`, `404`).
    pub status: u16,
    /// Response headers, lowercase-keyed and sorted (BTreeMap iteration
    /// is deterministic).
    pub headers: BTreeMap<String, String>,
    /// Response body as raw bytes. Handlers will base64-encode for the wire.
    pub body: Vec<u8>,
}

/// Convenience helper: parse a `BTreeMap<String, String>` (the JSON-on-wire
/// shape) into a real `HeaderMap`, lowercasing keys.
///
/// Returns `Error::Other("egress: invalid header ...")` for any name/value
/// that is not legal HTTP — this is a public-API safety net.
pub fn header_map_from_btree(input: &BTreeMap<String, String>) -> Result<HeaderMap> {
    let mut out = HeaderMap::new();
    for (k, v) in input.iter() {
        let name = HeaderName::try_from(k.to_ascii_lowercase().as_bytes())
            .map_err(|_| Error::Other("egress: invalid header name"))?;
        let value =
            HeaderValue::from_str(v).map_err(|_| Error::Other("egress: invalid header value"))?;
        out.insert(name, value);
    }
    Ok(out)
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_builds_with_default_config() {
        let _ = EgressClient::new().expect("egress client builds");
    }

    #[test]
    fn header_map_from_btree_lowercases_and_filters() {
        let mut m: BTreeMap<String, String> = BTreeMap::new();
        m.insert("Content-Type".into(), "application/json".into());
        m.insert("X-CUSTOM".into(), "1".into());
        let h = header_map_from_btree(&m).unwrap();
        assert!(h.contains_key("content-type"));
        assert!(h.contains_key("x-custom"));
    }

    #[test]
    fn header_map_from_btree_rejects_bad_name() {
        let mut m: BTreeMap<String, String> = BTreeMap::new();
        m.insert("Bad Header".into(), "1".into());
        let r = header_map_from_btree(&m);
        assert!(r.is_err());
    }

    #[test]
    fn header_map_from_btree_rejects_bad_value() {
        let mut m: BTreeMap<String, String> = BTreeMap::new();
        m.insert("X-Foo".into(), "bad\nvalue".into());
        let r = header_map_from_btree(&m);
        assert!(r.is_err());
    }
}
