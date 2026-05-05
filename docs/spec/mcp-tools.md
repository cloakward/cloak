# Cloak MCP tool spec

The Cloak MCP server exposes exactly **six** action-shaped tools to the model
surface. Schemas in this document are **authoritative** — they are
copy-paste of the JSON Schema (Draft 2020-12) literals in
`packages/cloak-mcp/src/tools/`. Tool descriptions are verbatim from the same
files; the description-contract test at
`packages/cloak-mcp/tests/tools.test.ts:163-200` fails CI if any of them drifts.

The single overarching invariant: **no tool returns plaintext secret material.**
This is enforced by the schemas (no `value` / `secret` / `plaintext` field is
ever populated), by the daemon (the CLI-only gate at
`crates/cloak-core/src/daemon.rs:300-308,420-427` keeps `vault.show` off the
MCP-callable surface), and by the per-tool plaintext-leak property test at
`packages/cloak-mcp/tests/tools.test.ts:140-161`.

## Tool registry

```ts
// packages/cloak-mcp/src/tools/index.ts:9-16
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
| `proxy_authenticated_http_request` | `tool.proxy_http` | status, headers, body |
| `mint_short_lived_token` | `tool.mint_token` | derived token + expiry |
| `query_audit` | `tool.query_audit` | audit entries (no values) |

---

## 1. `list_secret_names`

**Description (verbatim):**
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

**Description (verbatim):**
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

**Description (verbatim):**
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
    "secret_name": { "type": "string", "minLength": 1, "description": "Name of the stored secret to use as signing key." },
    "scheme":      { "type": "string", "enum": ["aws-sigv4", "hmac-sha256"], "description": "Signing scheme." },
    "method":      { "type": "string", "minLength": 1, "description": "HTTP method, e.g. GET, POST." },
    "url":         { "type": "string", "minLength": 1, "description": "Full request URL including query string." },
    "headers": {
      "type": "object",
      "additionalProperties": { "type": "string" },
      "description": "Optional request headers (case-insensitive keys handled by daemon)."
    },
    "body_b64":    { "type": "string", "description": "Optional base64-encoded request body." }
  },
  "required": ["secret_name", "scheme", "method", "url"],
  "additionalProperties": false
}
```

**Schemes:**

- `hmac-sha256` — daemon computes
  `HMAC-SHA256(key, "{METHOD}\n{URL}\n{sha256_hex(body)}\n")` and returns
  `{ "X-Cloak-Signature": "<lowercase hex>" }`.
- `aws-sigv4` — daemon shells through `aws-sigv4` to produce a real
  AWS-accepted SigV4 signature. The secret value must be in the form
  `<access_key_id>:<secret_access_key>`. KAT-verified against the published
  `get-vanilla` test vector (post-W1; see `CHANGELOG.md`).

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

**Description (verbatim):**
> Send an HTTP request to a host on the user's allowlist, with the named
> secret attached by the daemon as authentication. The request and response
> transit the local daemon, never this tool. Returns status, headers, and
> base64-encoded body. The auth header is stripped from the echoed request
> metadata. Use this to call APIs (GitHub, OpenAI, Stripe, etc.) without
> ever handling the key.

**Input schema:**
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "secret_name": { "type": "string", "minLength": 1, "description": "Name of the stored secret to attach as auth." },
    "method":      { "type": "string", "minLength": 1, "description": "HTTP method, e.g. GET, POST." },
    "url":         { "type": "string", "minLength": 1, "description": "Full request URL. Must be on the user's allowlist." },
    "headers": {
      "type": "object",
      "additionalProperties": { "type": "string" },
      "description": "Optional request headers. Auth header is added by the daemon."
    },
    "body_b64":    { "type": "string", "description": "Optional base64-encoded request body." },
    "auth_scheme": {
      "type": "string",
      "enum": ["bearer", "basic", "header", "query"],
      "description": "How to attach the secret: 'bearer' = Authorization: Bearer <s>; 'basic' = HTTP Basic; 'header' = custom header (provide header_name); 'query' = URL query parameter (provide query_name)."
    },
    "header_name": { "type": "string", "description": "Required when auth_scheme is 'header'." },
    "query_name":  { "type": "string", "description": "Required when auth_scheme is 'query'." }
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
| `query`  | Appends `?<query_name>=<secret>` to the URL |

The daemon strips any caller-supplied `Authorization`, `Cookie`, or
`X-Api-Key` headers before attaching its own — no smuggling.

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
become `<binary, N bytes>` (`packages/cloak-mcp/src/tools/proxy_authenticated_http_request.ts:50-82`).

The url's host must match `policy.toml::allowed_hosts`, evaluated by the
daemon before the secret is read.

---

## 5. `mint_short_lived_token`

**Description (verbatim):**
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

The parent secret is never echoed. The minted token is a derivative; rotating
the parent is a separate flow.

---

## 6. `query_audit`

**Description (verbatim):**
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
    "result": { "type": "string",  "description": "Filter by result tag (e.g. 'ok', 'denied', 'error')." },
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

---

## What is **not** in this surface

- No `get_secret`, `reveal_secret`, `read_secret`, or any other accessor that
  would return raw stored material to the model.
- No `vault.add`, `vault.set`, `vault.rm`, `vault.show` — those are CLI-only
  per `crates/cloak-core/src/daemon.rs:300-308,420-427`.
- No streaming, no bidirectional pushes — request/response only.

If you propose a new tool, it requires a Discussion + varun approval
(see `CONTRIBUTING.md` Hard rules and Escalation).
