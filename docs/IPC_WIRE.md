# Cloak IPC wire format (v1.0)

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
`confirmation-rejected`, `biometric-failed`, `aead-failure`,
`audit-broken`, `internal-error`.

Rate-limit exhaustion surfaces as `policy-denied` with the message
`rate limited` — the rate-limit bucket lives inside the policy engine
(`crates/cloak-core/src/handlers.rs:168-183`), so a single symbolic code
covers both rule-driven denials and bucket-driven denials.

The mapping from `cloak-core::Error` to wire `RpcError` is defined in
`crates/cloak-core/src/ipc.rs:104-150`. `unknown-method` and `vault-locked`
are emitted directly by the dispatcher
(`crates/cloak-core/src/daemon.rs:348-353,382-385`); they bypass the
`Error` enum and so do not appear in that table.

## Methods

### Session
- **`mcp.handshake`** — params `{}` → `{ "session_token": "..." }`. The daemon performs peer auth (UID, PID, code-signature) on the IPC connection and issues a token bound to that peer. The CLI uses `cli.handshake` instead (same semantics, different policy).
- **`cli.handshake`** — same as above, for the CLI peer.

### Vault operations

Vault creation and mutation (`init`, `add`, `set`, `rm`, import/export writes)
are performed by the `cloak` CLI directly against the local vault file. They
are not part of the production daemon IPC surface.

The daemon IPC surface exposes only the operations needed for MCP serving and
daemon-held unlock state:

- **`vault.is_initialized`** → `{ "initialized": bool }`
- **`vault.unlock`** — params `{ "passphrase": "..." }` → `{ "ok": true }` — **CLI peer only**.
- **`vault.lock`** → `{ "ok": true }` — **CLI peer only**.
- **`vault.show`** — params `{ name, skip_biometric? }` → `{ value: "..." }` — **CLI peer only**. Before producing any plaintext, `cloakd` itself fires the OS-level biometric / user-presence prompt (Touch ID on macOS, polkit `dev.cloak.show-secret` on Linux). The daemon ignores any client-supplied "user already approved" assertion and also ignores the legacy `skip_biometric` field: a same-UID attacker who connects to the socket directly cannot bypass the prompt by lying in the payload. On cancel / failure the daemon returns the `biometric-failed` error code.
- **`vault.status`** → `{ path, record_count, kdf_params, format_version, locked }`

### Read-only metadata (CLI and MCP)
- **`vault.list`** → `{ secrets: [{ name, kind, tags, created_at, updated_at, version }, ...] }`
- **`vault.get_metadata`** — params `{ name }` → metadata row.

### Privileged tool handlers (MCP-callable; subject to policy)
- **`tool.sign_request`** — params `{ secret_name, scheme, method, url, headers?, body_b64? }` → `{ headers: {...} }`. `scheme ∈ {"aws-sigv4","hmac-sha256"}`.
- **`tool.proxy_http`** — params `{ secret_name, method, url, headers?, body_b64?, auth_scheme, header_name? }` → `{ status, headers, body_b64, redacted }`. The daemon enforces the `allowed_hosts` policy, supports `auth_scheme ∈ {"bearer","basic","header"}`, and rejects query-string auth because URLs are commonly logged. Before returning the upstream response, Cloak redacts exact representations of the attached secret and marks `redacted=true` if anything changed; the response still goes to the MCP client and must come from a host the user trusts.
- **`tool.mint_token`** — params `{ secret_name, kind, scope?, ttl_seconds? }` → `{ token, expires_at }`. `kind ∈ {"aws-sts","github-app","gitlab-pat"}`. v1.0 ships `aws-sts` as a real impl (calls AWS STS `GetSessionToken`); `github-app` and `gitlab-pat` schemas are stable but the handlers return a typed not-supported error (still policy-checked, rate-limited, and audited). The returned token is a derived credential visible to the MCP client.
- **`tool.query_audit`** — params `{ since?, until?, tool?, secret?, result?, limit? }` → `{ entries: [...] }`. Entries never contain secret values.

## Auth & sessions

1. The daemon accepts the connection and reads kernel peer credentials (UID, PID, audit token on macOS).
2. The daemon resolves the peer binary path, hashes its executable image, and checks the hash against trusted `cloak` / `cloak-mcp` binaries installed next to `cloakd`. On Linux it prefers the kernel-pinned `/proc/<pid>/exe` bytes and falls back to the resolved executable path only when procfs denies opening the sibling process image. On macOS it also compares the running process CodeDirectory hash reported by the kernel. Unknown or hash-mismatched peer → connection closed with `peer-not-trusted` *before* any session token is issued.
3. The peer calls `*.handshake`. `cli.handshake` is accepted only from `cloak`; `mcp.handshake` is accepted only from `cloak-mcp`. The daemon issues a session token bound to `(peer_pid, peer_identity, code_sig_hash, conn_id, expires_at=now+30min)`.
4. Subsequent requests carry `session_token`. The daemon validates token + connection identity. If the peer process exits, the token is invalidated (kqueue `EVFILT_PROC` on macOS, PIDFD close on Linux).

## What is NOT in this contract

- Plaintext stored-secret retrieval over MCP. There is **no** method named `get_secret`, `reveal_secret`, or anything equivalent on the MCP-callable surface. `vault.show` is gated to the CLI peer. This is enforced by both peer-identity checks and policy.
- Streaming. v1.0 is request/response only.
- Bi-directional pushes or confirmation callbacks. v1.0 is request/response only; policy `RequireConfirmation` decisions fail closed as `policy-denied` until a real confirmation UX exists.
