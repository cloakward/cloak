# Cloak MCP tool spec

The Cloak MCP server exposes exactly **six** action-shaped tools to the model
surface. This document is the human-readable reference; the source of truth for
JSON Schema literals and tool text is `packages/cloak-mcp/src/tools/`.

The single overarching invariant: **no tool returns raw stored secret values.**
This is enforced by the schemas (no stored-secret `value` / `plaintext` field is
ever populated), by the daemon (`crates/cloak-core/src/daemon.rs` keeps
`vault.show`, `vault.unlock`, and `vault.lock` off the MCP-callable surface), and
by the per-tool plaintext-leak property tests in
`packages/cloak-mcp/tests/tools.test.ts`.

Two outputs still need to be treated as credentials or sensitive data:
`mint_short_lived_token` intentionally returns a derived credential to the MCP
client, and `proxy_authenticated_http_request` returns the upstream response
body and headers. Cloak redacts exact representations of the attached secret,
but it cannot prove that a remote API will never echo transformed credentials or
unrelated sensitive data in its response.

## Tool registry

```ts
// packages/cloak-mcp/src/tools/index.ts
export const tools: ReadonlyArray<CloakTool> = [
  listSecretNames,
  getSecretMetadata,
  signRequest,
  proxyAuthenticatedHttpRequest,
  mintShortLivedToken,
  queryAudit,
];
```

| Tool | Backing method | Returns |
|---|---|---|
| `list_secret_names` | `vault.list` | metadata array (no values) |
| `get_secret_metadata` | `vault.get_metadata` | metadata row (no value) |
| `sign_request` | `tool.sign_request` | computed auth headers |
| `proxy_authenticated_http_request` | `tool.proxy_http` | upstream status, headers, body |
| `mint_short_lived_token` | `tool.mint_token` | derived credential + expiry |
| `query_audit` | `tool.query_audit` | audit entries (no values) |

---

## 1. `list_secret_names`

**Description:**
> List the names and metadata of secrets stored in the local Cloak vault.
> Returns names, kinds, and tags only — never the secret values themselves.

**Input schema:**
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {},
  "additionalProperties": false
}
```

**Example request (MCP `tools/call`):**
```json
{ "name": "list_secret_names", "arguments": {} }
```

**Example daemon response:**
```json
{
  "secrets": [
    { "name": "OPENAI_API_KEY",  "kind": "api_key",     "tags": ["llm"], "created_at": "2026-04-30T12:00:00Z", "updated_at": "2026-04-30T12:00:00Z", "version": 1 },
    { "name": "GITHUB_PAT",      "kind": "oauth_token", "tags": ["scm"], "created_at": "2026-05-01T09:14:00Z", "updated_at": "2026-05-01T09:14:00Z", "version": 1 }
  ]
}
```

The shim returns the daemon body verbatim as the tool result text. No values.

---

## 2. `get_secret_metadata`

**Description:**
> Return metadata about a single named secret (kind, tags, created/updated
> timestamps, version). Never returns the secret value.

**Input schema:**
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "name": { "type": "string", "minLength": 1, "description": "The secret name." }
  },
  "required": ["name"],
  "additionalProperties": false
}
```

**Example request:**
```json
{ "name": "get_secret_metadata", "arguments": { "name": "OPENAI_API_KEY" } }
```

**Example daemon response:**
```json
{
  "name": "OPENAI_API_KEY",
  "kind": "api_key",
  "tags": ["llm"],
  "created_at": "2026-04-30T12:00:00Z",
  "updated_at": "2026-04-30T12:00:00Z",
  "version": 1
}
```

---

## 3. `sign_request`

**Description:**
> Compute authentication headers for an outbound HTTP request using a stored
> secret as the signing key. Supports AWS SigV4 and generic HMAC-SHA256.
> Returns only the computed headers — the underlying secret is never
> disclosed. Use this when an API requires request signing rather than a
> bearer token.

**Input schema:**
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "secret_name": { "type": "string", "minLength": 1, "maxLength": 256, "description": "Name of the stored secret to use as signing key." },
    "scheme":      { "type": "string", "enum": ["aws-sigv4", "hmac-sha256"], "description": "Signing scheme." },
    "method":      { "type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"], "description": "HTTP method." },
    "url":         { "type": "string", "format": "uri", "pattern": "^https?://", "maxLength": 8192, "description": "Full http(s) request URL including query string. URL username/password and credential-shaped query parameters are rejected." },
    "headers": {
      "type": "object",
      "additionalProperties": { "type": "string" },
      "description": "Optional request headers (case-insensitive keys handled by daemon). Credential-bearing input headers are rejected."
    },
    "body_b64":    { "type": "string", "description": "Optional standard base64-encoded request body." },
    "aws_region":  { "type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z0-9-]+$", "description": "AWS SigV4 region, for example us-east-1. Used only when scheme is aws-sigv4." },
    "aws_service": { "type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z0-9-]+$", "description": "AWS SigV4 service, for example execute-api or s3. Used only when scheme is aws-sigv4." }
  },
  "required": ["secret_name", "scheme", "method", "url"],
  "additionalProperties": false
}
```

**Schemes:**

- `hmac-sha256` — daemon computes
  `HMAC-SHA256(key, "{METHOD}\n{URL}\n{sha256_hex(body)}\n")` and returns
  `{ "X-Cloak-Signature": "<lowercase hex>" }`.
- `aws-sigv4` — daemon signs in-process with the Rust `aws-sigv4` crate. The
  secret value must be in the form `<access_key_id>:<secret_access_key>`.
  `aws_region` defaults to `us-east-1` and `aws_service` defaults to
  `execute-api` when omitted. KAT-verified against the published `get-vanilla`
  test vector.

**Example request:**
```json
{
  "name": "sign_request",
  "arguments": {
    "secret_name": "STRIPE_WEBHOOK_KEY",
    "scheme": "hmac-sha256",
    "method": "POST",
    "url": "https://example.com/hook",
    "body_b64": "eyJob29rIjoidGVzdCJ9"
  }
}
```

**Example daemon response:**
```json
{
  "headers": { "X-Cloak-Signature": "8f1c…" }
}
```

The response only contains the computed auth headers. The original headers,
body, and signing key never appear in the response and are never logged.

---

## 4. `proxy_authenticated_http_request`

**Description:**
> Send an HTTPS request to a host on the user's allowlist, with the named
> secret attached by the daemon as bearer, basic, or custom-header
> authentication. Returns status, redacted headers, and base64-encoded body.
> Query-string auth is disabled because URLs are commonly logged.

**Input schema:**
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "secret_name": { "type": "string", "minLength": 1, "description": "Name of the stored secret to attach as auth." },
    "method":      { "type": "string", "minLength": 1, "description": "HTTP method, e.g. GET, POST." },
    "url":         { "type": "string", "minLength": 1, "description": "Full HTTPS request URL. Must be on the user's allowlist and must not include URL username/password or credential-shaped query parameters." },
    "headers": {
      "type": "object",
      "additionalProperties": { "type": "string" },
      "description": "Optional request headers. Auth header is added by the daemon; credential-bearing input headers are rejected by the MCP schema and stripped defensively by the daemon."
    },
    "body_b64":    { "type": "string", "description": "Optional base64-encoded request body." },
    "auth_scheme": {
      "type": "string",
      "enum": ["bearer", "basic", "header"],
      "description": "How to attach the secret: 'bearer' = Authorization: Bearer <s>; 'basic' = HTTP Basic; 'header' = custom header (provide header_name). Query-string auth is disabled because URLs are commonly logged."
    },
    "header_name": { "type": "string", "description": "Required when auth_scheme is 'header'." }
  },
  "required": ["secret_name", "method", "url", "auth_scheme"],
  "additionalProperties": false
}
```

**Auth schemes:**

| `auth_scheme` | Daemon behavior |
|---|---|
| `bearer` | Adds `Authorization: Bearer <secret>` |
| `basic`  | Adds `Authorization: Basic base64(secret)` (secret should be `user:pass`) |
| `header` | Adds `<header_name>: <secret>` |

The daemon strips any caller-supplied `Authorization`, `Cookie`, or
credential-shaped headers before attaching its own — no smuggling.

Caveat: the upstream response is returned to the MCP client. Cloak redacts exact
secret forms from response body/headers and marks `redacted=true` if it changed
anything, but transformed credentials, submitted bodies, and unrelated sensitive
data can still appear in a remote response. Only allow hosts whose response
behavior you trust.

**Example request:**
```json
{
  "name": "proxy_authenticated_http_request",
  "arguments": {
    "secret_name": "OPENAI_API_KEY",
    "method": "GET",
    "url": "https://api.openai.com/v1/models",
    "auth_scheme": "bearer"
  }
}
```

**Example daemon response (post-`formatProxyResponse`):**
```
Status 200
content-type: application/json
date: Sun, 04 May 2026 10:00:00 GMT

{"object":"list","data":[…]}
```

The shim renders status / headers / body as plain text. Binary bodies
become `<binary, N bytes>` in
`packages/cloak-mcp/src/tools/proxy_authenticated_http_request.ts`.

The url's host must match `policy.toml::allowed_hosts`, evaluated by the
daemon before the secret is read.

---

## 5. `mint_short_lived_token`

**Description:**
> Mint a short-lived derived token from a long-lived parent secret. Examples:
> STS session credentials from an AWS access key, an installation token from
> a GitHub App private key, a scoped PAT from a parent PAT. Returns the
> derived token and its expiry. The long-lived parent never leaves the
> daemon.

**Input schema:**
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "secret_name": { "type": "string", "minLength": 1, "description": "Name of the parent (long-lived) secret." },
    "kind": {
      "type": "string",
      "enum": ["aws-sts", "github-app", "gitlab-pat"],
      "description": "What flavor of derived token to mint."
    },
    "scope": {
      "type": "object",
      "description": "Optional scope/claims object passed to the minting backend (e.g. STS RoleArn, GitHub repo set).",
      "additionalProperties": true
    },
    "ttl_seconds": {
      "type": "integer",
      "minimum": 1,
      "description": "Optional requested lifetime in seconds. Daemon may cap to a policy-defined maximum."
    }
  },
  "required": ["secret_name", "kind"],
  "additionalProperties": false
}
```

**Implemented kinds (v1.0):**

- `aws-sts` — calls real AWS STS `GetSessionToken` (post-W1) and returns a
  base64'd JSON envelope of the temporary credentials with an RFC3339
  `expires_at`. The parent secret value must be `<access_key_id>:<secret_access_key>`.
- `github-app` / `gitlab-pat` — schema is stable but the handlers return a
  typed not-supported error. Calls are still policy-checked, rate-limited,
  and audited.

**Example request:**
```json
{
  "name": "mint_short_lived_token",
  "arguments": {
    "secret_name": "AWS_ROOT_ACCESS_KEY",
    "kind": "aws-sts",
    "ttl_seconds": 3600
  }
}
```

**Example daemon response:**
```json
{
  "token": "eyJBY2Nlc3NLZXlJZCI6Ik…fQ==",
  "expires_at": "2026-05-04T11:00:00Z"
}
```

The parent secret is never echoed. The minted token is a derived credential that
the MCP client receives by design, and it can authorize actions until it
expires. Rotating the parent is a separate flow.

---

## 6. `query_audit`

**Description:**
> Query the local Cloak audit log of privileged operations. Filterable by
> time range, tool name, secret name, and result. Returns audit entries —
> never secret values.

**Input schema:**
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "since":  { "type": "string",  "description": "Inclusive lower bound (RFC3339 timestamp) for audit entries." },
    "until":  { "type": "string",  "description": "Exclusive upper bound (RFC3339 timestamp) for audit entries." },
    "tool":   { "type": "string",  "description": "Filter by tool name (e.g. 'sign_request')." },
    "secret": { "type": "string",  "description": "Filter by secret name." },
    "result": { "type": "string",  "description": "Filter by result tag (e.g. 'started', 'ok', 'denied', 'error')." },
    "limit":  { "type": "integer", "minimum": 1, "description": "Maximum number of entries to return." }
  },
  "required": [],
  "additionalProperties": false
}
```

**Example request:**
```json
{
  "name": "query_audit",
  "arguments": {
    "since": "2026-05-04T00:00:00Z",
    "tool": "proxy_http",
    "result": "denied",
    "limit": 10
  }
}
```

**Example daemon response:**
```json
{
  "entries": [
    {
      "ts": "2026-05-04T09:14:01Z",
      "peer": { "pid": 4221, "basename": "cloak-mcp" },
      "tool": "tool.proxy_http",
      "secret": "STRIPE_API_KEY",
      "target": "evil.example.org",
      "result": "denied",
      "note": "denied: host not in allowed_hosts",
      "prev_hash": "9af3…",
      "seq": 117
    }
  ]
}
```

Entries never contain secret values. The `prev_hash` chains each entry to
the previous; `cloak audit verify` recomputes the chain and rejects any
mutated, deleted, or reordered line.

Network side-effecting tools write a `started` entry before the outbound
request and a final `ok` or `error` entry after it returns.

---

## What is **not** in this surface

- No `get_secret`, `reveal_secret`, `read_secret`, or any other accessor that
  would return raw stored material to the model.
- No `vault.add`, `vault.set`, `vault.rm`, `vault.show` — write/reveal methods
  are CLI-only in `crates/cloak-core/src/daemon.rs`.
- No streaming, no bidirectional pushes — request/response only.

If you propose a new tool, it requires a Discussion + varun approval
(see `CONTRIBUTING.md` Hard rules and Escalation).
