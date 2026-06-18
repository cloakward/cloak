//! Outbound HTTP - the *only* place outbound HTTP lives in the workspace.
//!
//! `cloak-mcp` MUST NOT import any HTTP client. Every privileged tool that
//! needs to talk to the network goes through this module.
//!
//! Build a single `EgressClient` at daemon start and reuse it. The client
//! is configured with:
//! - rustls TLS (no native-tls / OpenSSL),
//! - redirects disabled (no credential forwarding across hosts/schemes),
//! - a 30-second total timeout per request,
//! - an SSRF guard that refuses to connect to any non-global IP address
//!   (loopback, private, link-local incl. cloud-metadata `169.254.169.254`,
//!   ULA, etc.) - for both IP-literal hosts *and* hostnames, validated at the
//!   exact resolution reqwest connects to, so DNS-rebinding cannot slip a
//!   private address past the host allowlist.
//!
//! Transport failures are surfaced as `Error::Other("egress: ...")` -
//! short, static-ish strings; they never carry secret material.
//!
//! Defense-in-depth note: this module does NOT perform host *allowlist*
//! checks. Those live in `handlers::proxy_http` and run **before** the request
//! is built. Egress owns the I/O *and* the address-class SSRF backstop: the
//! allowlist answers "which hostnames may I talk to", egress answers "this
//! resolved to a private/metadata address, refuse regardless".

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use url::{Host, Url};

use crate::error::{Error, Result};

/// Wrapper around a long-lived `reqwest::Client` configured for cloak's
/// outbound calls. Build once at daemon startup; clone is cheap.
#[derive(Clone)]
pub struct EgressClient {
    inner: reqwest::Client,
}

impl EgressClient {
    /// Construct a fresh client with rustls TLS, redirects disabled, and a
    /// 30-second per-request timeout. Returns `Error::Other` (never panics)
    /// if the underlying builder fails.
    pub fn new() -> Result<Self> {
        let inner = reqwest::Client::builder()
            .use_rustls_tls()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            // SSRF backstop for hostnames: reqwest connects to exactly the
            // addresses this resolver returns, so a name that resolves to a
            // private/metadata address is dropped at the same resolution used
            // for the connection - defeating DNS-rebinding.
            .dns_resolver(Arc::new(GuardedResolver))
            .build()
            .map_err(|_| Error::Other("egress: failed to build http client"))?;
        Ok(Self { inner })
    }

    /// Execute a fully-formed `PreparedRequest` and collect the response
    /// into a `RawResponse` (status + lowercased-key headers + bytes body).
    ///
    /// Errors:
    /// - DNS / connect / TLS / read errors → `Error::Other("egress: ...")`.
    /// - HTTP 4xx/5xx are *not* errors here - the caller decides what to
    ///   do with the status code.
    pub async fn execute(&self, req: PreparedRequest) -> Result<RawResponse> {
        self.execute_with_body_limit(req, usize::MAX).await
    }

    /// Execute a request while refusing to buffer more than `max_body_bytes`.
    pub async fn execute_with_body_limit(
        &self,
        req: PreparedRequest,
        max_body_bytes: usize,
    ) -> Result<RawResponse> {
        // SSRF backstop for IP-literal hosts. reqwest does NOT invoke the DNS
        // resolver when the URL host is already an IP literal, so a literal
        // like `https://169.254.169.254/` would bypass `GuardedResolver`.
        // Reject non-global literals here, before any connection is opened.
        if let Some(host) = req.url.host() {
            let literal = match host {
                Host::Ipv4(v4) => Some(IpAddr::V4(v4)),
                Host::Ipv6(v6) => Some(IpAddr::V6(v6)),
                Host::Domain(_) => None,
            };
            if let Some(ip) = literal {
                if ip_is_disallowed(&ip) && !egress_allows_non_global() {
                    return Err(Error::Other("egress: refused non-global address"));
                }
            }
        }

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
        let mut body = Vec::new();
        let mut resp = resp;
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|_| Error::Other("egress: body read failed"))?
        {
            if body.len().saturating_add(chunk.len()) > max_body_bytes {
                return Err(Error::Other("egress: response body too large"));
            }
            body.extend_from_slice(&chunk);
        }
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

/// A captured HTTP response - status, lowercase-keyed sorted header map,
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
/// that is not legal HTTP - this is a public-API safety net.
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
// SSRF guard - refuse non-global destination addresses
// -------------------------------------------------------------------------

/// Whether non-global destinations are permitted. **Always `false` in
/// production builds.** Only test / `test-util` builds may opt in (the same
/// `CLOAK_TEST_ALLOW_HTTP_EGRESS` switch the proxy round-trip test uses to
/// reach a `127.0.0.1` mock server), so the SSRF backstop can never be
/// disabled in a shipped daemon.
fn egress_allows_non_global() -> bool {
    #[cfg(any(test, feature = "test-util"))]
    {
        std::env::var_os("CLOAK_TEST_ALLOW_HTTP_EGRESS").is_some()
    }
    #[cfg(not(any(test, feature = "test-util")))]
    {
        false
    }
}

/// True if `ip` is anything other than a normal, globally-routable unicast
/// address - i.e. one we must refuse to connect to from a model-driven proxy.
/// `Ipv4Addr::is_global`/`Ipv6Addr::is_global` are still unstable, so this is
/// an explicit deny-list of the relevant special-use ranges.
fn ip_is_disallowed(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => ipv4_disallowed(*v4),
        IpAddr::V6(v6) => ipv6_disallowed(*v6),
    }
}

fn ipv4_disallowed(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_unspecified()        // 0.0.0.0
        || ip.is_loopback()    // 127.0.0.0/8
        || ip.is_private()     // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()  // 169.254.0.0/16 - incl. 169.254.169.254 metadata
        || ip.is_broadcast()   // 255.255.255.255
        || ip.is_documentation() // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || o[0] == 0                                   // 0.0.0.0/8 "this network"
        || (o[0] == 100 && (0x40..0x80).contains(&o[1])) // 100.64.0.0/10 CGNAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)     // 192.0.0.0/24 IETF protocol
        || (o[0] == 192 && o[1] == 88 && o[2] == 99)   // 192.88.99.0/24 6to4 relay
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // 198.18.0.0/15 benchmarking
        || o[0] >= 240 // 240.0.0.0/4 reserved
}

fn ipv6_disallowed(ip: Ipv6Addr) -> bool {
    // Unwrap IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d)
    // forms and judge them by their embedded v4 address, so e.g.
    // `::ffff:169.254.169.254` cannot smuggle the metadata IP past us.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return ipv4_disallowed(v4);
    }
    let s = ip.segments();
    if s[0..6] == [0, 0, 0, 0, 0, 0] && (s[6] != 0 || s[7] != 0) {
        let v4 = Ipv4Addr::new(
            (s[6] >> 8) as u8,
            (s[6] & 0xff) as u8,
            (s[7] >> 8) as u8,
            (s[7] & 0xff) as u8,
        );
        // ::1 is loopback (handled below); only treat larger embedded v4 as v4.
        if !ip.is_loopback() {
            return ipv4_disallowed(v4);
        }
    }
    ip.is_unspecified()                  // ::
        || ip.is_loopback()              // ::1
        || ip.is_multicast()             // ff00::/8
        || (s[0] & 0xfe00) == 0xfc00     // fc00::/7 unique-local
        || (s[0] & 0xffc0) == 0xfe80     // fe80::/10 link-local
        || (s[0] == 0x2001 && s[1] == 0x0db8) // 2001:db8::/32 documentation
}

/// A reqwest DNS resolver that performs normal system resolution and then
/// drops any non-global address before reqwest connects. If a name resolves
/// only to disallowed addresses the resolution fails closed.
struct GuardedResolver;

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let resolved = tokio::task::spawn_blocking(move || {
                // Port is irrelevant for address-class filtering; reqwest
                // overrides it with the URL's port for the actual connection.
                (host.as_str(), 0u16)
                    .to_socket_addrs()
                    .map(|it| it.collect::<Vec<SocketAddr>>())
            })
            .await;

            let addrs: Vec<SocketAddr> = match resolved {
                Ok(Ok(addrs)) => addrs,
                // Join error or resolution error → fail closed, no detail leak.
                _ => return Err("egress: dns resolution failed".into()),
            };

            let allow_non_global = egress_allows_non_global();
            let vetted: Vec<SocketAddr> = addrs
                .into_iter()
                .filter(|a| allow_non_global || !ip_is_disallowed(&a.ip()))
                .collect();

            if vetted.is_empty() {
                return Err("egress: refused non-global address".into());
            }
            Ok(Box::new(vetted.into_iter()) as reqwest::dns::Addrs)
        })
    }
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
    fn disallows_loopback_private_linklocal_and_metadata() {
        for s in [
            "127.0.0.1",
            "0.0.0.0",
            "10.0.0.5",
            "172.16.9.9",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "100.64.0.1",      // CGNAT
            "198.18.0.1",      // benchmarking
            "192.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:169.254.169.254", // v4-mapped metadata
            "::ffff:10.0.0.1",
        ] {
            let ip: IpAddr = s.parse().unwrap_or_else(|_| panic!("parse {s}"));
            assert!(ip_is_disallowed(&ip), "{s} should be refused");
        }
    }

    #[test]
    fn allows_normal_global_addresses() {
        for s in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",        // example.com
            "172.32.0.1",           // just outside 172.16/12
            "100.63.255.255",       // just outside CGNAT
            "100.128.0.1",          // just outside CGNAT
            "2606:4700:4700::1111", // cloudflare v6
            "2001:4860:4860::8888", // google v6
        ] {
            let ip: IpAddr = s.parse().unwrap_or_else(|_| panic!("parse {s}"));
            assert!(!ip_is_disallowed(&ip), "{s} should be allowed");
        }
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

    #[tokio::test]
    async fn execute_refuses_ip_literal_metadata_host() {
        // No CLOAK_TEST_ALLOW_HTTP_EGRESS in this (lib unittest) binary, so the
        // SSRF backstop is active. The literal must be refused before any
        // connection is attempted.
        let client = EgressClient::new().expect("client");
        let req = PreparedRequest {
            method: reqwest::Method::GET,
            url: Url::parse("https://169.254.169.254/latest/meta-data/").unwrap(),
            headers: HeaderMap::new(),
            body: None,
        };
        match client.execute(req).await {
            Err(Error::Other(m)) => assert!(m.contains("non-global"), "got: {m}"),
            other => panic!("expected non-global refusal, got: {other:?}"),
        }
    }
}
