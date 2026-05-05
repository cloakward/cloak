# Cloak IPC wire format (v0.1)

This is the **frozen** contract between `cloakd` (the daemon, Rust) and its peers (`cloak` CLI in Rust, `cloak-mcp` in TypeScript/Bun). All four code paths agree on the shapes here.

## Transport

- **macOS / Linux**: Unix domain socket at `${XDG_RUNTIME_DIR}/cloakd.sock` if set, else `${TMPDIR:-/tmp}/cloakd-$UID.sock`.
- **Windows** (deferred): Named Pipe `\\.\pipe\cloakd-<sid>`.

The socket file is created with mode `0600`. The daemon refuses connections from peers whose effective UID does not match its own (the kernel-level peer-cred check is the first gate).

## Framing

Length-prefixed JSON.

```
+----------------+-------------------------+
| u32 LE length  | UTF-8 JSON body (length bytes) |
+----------------+-------------------------+
```

- Max frame size: **4 MiB**. Frames exceeding this are rejected; the daemon closes the connection.
- The JSON body must parse cleanly. Malformed JSON → connection closed.
- Both directions use the same framing.

## Request shape

```json
{
  "id": "<uuid v4>",
  "method": "<dotted.method.name>",
  "params": { ... },
  "session_token": "<opaque base64; omitted on handshake>"
}
```

## Response shape

```json
{ "id": "<same uuid>", "result": { ... } }
```

or

```json
{ "id": "<same uuid>", "error": { "code": "<symbolic>", "message": "human-readable" } }
```

Error codes are symbolic, lowercase-kebab. Defined codes:
`peer-not-trusted`, `session-expired`, `unknown-method`, `invalid-params`,
`vault-locked`, `secret-not-found`, `secret-exists`, `policy-denied`,
`confirmation-rejected`, `rate-limited`, `aead-failure`, `audit-broken`,
`internal-error`.

## Methods

### Session
- **`mcp.handshake`** — params `{}` → `{ "session_token": "..." }`. The daemon performs peer auth (UID, PID, code-signature) on the IPC connection and issues a token bound to that peer. The CLI uses `cli.handshake` instead (same semantics, different policy).
- **`cli.handshake`** — same as above, for the CLI peer.

### Vault management (CLI-only — not exposed to MCP)
- **`vault.is_initialized`** → `{ "initialized": bool }`
- **`vault.initialize`** — params `{ "passphrase": "..." }` → `{ "kdf_params": {...} }`
- **`vault.unlock`** — params `{ "passphrase": "..." }` → `{ "ok": true }`
- **`vault.lock`** → `{ "ok": true }`
- **`vault.add`** — params `{ name, kind, tags, value }` → `{ ok: true, version: 1 }`
- **`vault.set`** — params `{ name, value }` → `{ ok: true, version: N }`
- **`vault.rm`** — params `{ name }` → `{ ok: true }`
- **`vault.show`** — params `{ name }` → `{ value: "..." }` — **CLI peer only**, requires biometric flag from CLI in `params.biometric_ok: true`.
- **`vault.status`** → `{ path, record_count, kdf_params, format_version, locked }`

### Read-only metadata (CLI and MCP)
- **`vault.list`** → `{ secrets: [{ name, kind, tags, created_at, updated_at, version }, ...] }`
- **`vault.get_metadata`** — params `{ name }` → metadata row.

### Privileged tool handlers (MCP-callable; subject to policy)
- **`tool.sign_request`** — params `{ secret_name, scheme, method, url, headers?, body_b64? }` → `{ headers: {...} }`. `scheme ∈ {"aws-sigv4","hmac-sha256"}`.
- **`tool.proxy_http`** — params `{ secret_name, method, url, headers?, body_b64?, auth_scheme, header_name?, query_name? }` → `{ status, headers, body_b64 }`. The daemon enforces the `allowed_hosts` policy and strips the auth header from any echoed metadata.
- **`tool.mint_token`** — params `{ secret_name, kind, scope?, ttl_seconds? }` → `{ token, expires_at }`. `kind ∈ {"aws-sts","github-app","gitlab-pat"}`. v0.1 ships `aws-sts` only as a working impl; the rest may return `unknown-method` or `not-implemented` errors but their schemas are stable.
- **`tool.query_audit`** — params `{ since?, until?, tool?, secret?, result?, limit? }` → `{ entries: [...] }`. Entries never contain secret values.

## Auth & sessions

1. The daemon accepts the connection and reads kernel peer credentials (UID, PID, audit token on macOS).
2. The daemon resolves the peer binary path, hashes its on-disk image (or its mach-o code-directory hash on macOS), and checks against an allowlist (`cloak`, `cloak-mcp`). Unknown peer → connection closed with `peer-not-trusted` *before* any session token is issued.
3. The peer calls `*.handshake`. The daemon issues a session token bound to `(peer_pid, code_sig_hash, conn_id, expires_at=now+30min)`.
4. Subsequent requests carry `session_token`. The daemon validates token + connection identity. If the peer process exits, the token is invalidated (kqueue `EVFILT_PROC` on macOS, PIDFD close on Linux).

## What is NOT in this contract

- Plaintext secret retrieval over MCP. There is **no** method named `get_secret`, `reveal_secret`, or anything equivalent on the MCP-callable surface. `vault.show` is gated to the CLI peer. This is enforced by both peer-identity checks and policy.
- Streaming. v0.1 is request/response only.
- Bi-directional pushes. The daemon issues confirmation prompts via a separate side-channel (CLI invocation + desktop notification), not over the IPC reply channel.
