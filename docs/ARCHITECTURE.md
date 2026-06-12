# Cloak architecture

> Companion to `README.md` and `docs/THREAT_MODEL.md`. This document
> describes how the three Cloak processes fit together, where the trust
> boundary sits, and how a request flows from a Claude tool call to a
> decrypted-then-discarded secret on the wire.

## Three processes, one trust boundary

```mermaid
flowchart LR
  subgraph Untrusted["model surface (untrusted)"]
    CD[Claude Desktop / Claude Code]
  end

  subgraph Shim["IPC shim (no raw stored secrets, no HTTP)"]
    MCP[cloak-mcp<br/>Bun, TypeScript]
  end

  subgraph Trusted["trusted local daemon (Rust)"]
    DAEMON[cloakd<br/>vault + policy + audit + egress]
    VAULT[(vault.cloak<br/>SQLite WAL, AEAD-sealed)]
  end

  subgraph User["interactive user (trusted)"]
    CLI[cloak CLI<br/>Rust]
  end

  CD -- "MCP / stdio" --> MCP
  MCP -- "length-prefixed JSON over UDS" --> DAEMON
  CLI -- "length-prefixed JSON over UDS" --> DAEMON
  CLI -. "library-direct (legacy vault ops)" .-> VAULT
  DAEMON -- "proxy: reqwest + rustls<br/>STS: AWS Smithy client" --> Internet[(remote APIs<br/>policy-controlled)]
  DAEMON --> VAULT
```

The trust boundary is the UDS at `$XDG_RUNTIME_DIR/cloakd.sock` when
`XDG_RUNTIME_DIR` is set, else `${TMPDIR:-/tmp}/cloakd-$UID.sock`.
Everything to the left of it is treated as untrusted: the MCP shim has zero
authority of its own; it is a typed wire-format adapter. Everything to the
right of it owns the master key, the policy file, the audit log, and all
outbound HTTP.

There are exactly four parties in the system. They communicate by exactly
two protocols.

| Party | Implementation | Trust class | Speaks |
|---|---|---|---|
| Claude Desktop / Claude Code | external | **untrusted** (model output) | MCP |
| `cloak-mcp` shim | Bun, TS, single binary | **policy-bridge** (no raw stored secrets, no HTTP) | MCP ↔ Cloak IPC |
| `cloakd` daemon | Rust, Tokio, libsodium | **trusted** (owns the vault) | Cloak IPC, outbound HTTPS |
| `cloak` CLI | Rust, clap | **trusted** (user-driven) | Cloak IPC, library-direct vault access for local setup and user-present vault operations |

The CLI is dual-mode: daemon/session operations use the same IPC path as
`cloak-mcp`, while local setup and user-present vault operations open the
SQLite file directly. Moving all CLI operations onto IPC is a future hardening
step, not a shipped guarantee.

## The IPC contract

Frozen and documented separately at `docs/IPC_WIRE.md`. The TL;DR:

- Length-prefixed JSON, 4 MiB cap, both directions.
- Symbolic, lowercase-kebab error codes (`peer-not-trusted`, `vault-locked`,
  `policy-denied`, `aead-failure`, `audit-broken`, …).
- Methods are dotted (`mcp.handshake`, `vault.list`, `tool.sign_request`).
- Every method except `*.handshake` carries a `session_token` bound to
  `(peer_pid, peer_basename, conn_id, expires_at)`.

The Rust side of the framing lives in `crates/cloak-core/src/ipc.rs`. The
TypeScript side lives in `packages/cloak-mcp/src/ipc.ts`. Both implementations
agree on `MAX_FRAME_SIZE = 4 * 1024 * 1024`. The `Error → RpcError` mapping
is at `crates/cloak-core/src/ipc.rs:104-150`.

### Peer authentication

Before the daemon issues any session token, it resolves the peer's
credentials from the kernel and gates them through `peer_auth::check()`.

- **macOS** (`crates/cloak-core/src/peer_auth.rs`): `getsockopt(SOL_LOCAL,
  LOCAL_PEERTOKEN)` for PID plus non-recycling audit-token identity,
  `getpeereid(2)` for UID/GID, `proc_pidpath(3)` for the binary path, and
  `csops(CS_OPS_CDHASH)` for the running process CodeDirectory hash. The
  daemon checks both the on-disk SHA-256 and CodeDirectory hash against the
  installed trusted binaries.
- **Linux** (`crates/cloak-core/src/peer_auth.rs`): `SO_PEERCRED` for
  PID/UID/GID, `SO_PEERPIDFD` for non-recycling pidfd identity, and the
  `/proc/<pid>/exe` magic symlink for the binary. The trust hash is taken from
  the `/proc/<pid>/exe` symlink itself (which the kernel pins to the actual
  executed inode), **not** by re-reading the resolved path by name - so a
  same-UID attacker cannot restore trusted bytes at the path after launching a
  different executable. Linux has no running-process code-directory equivalent,
  so the residual exec-after-connect race is inherent to the same-UID model.
- **The default allowlist** (`crates/cloak-core/src/peer_auth.rs`) is
  the installed `cloak` and `cloak-mcp` sibling binaries. `cloakd` is never
  accepted as a client peer. Same UID is required.

The binary hash check is a startup pin over installed files, not a global
code-signature authority. It rejects renamed binaries and on-disk path
restoration (Linux hashes the pinned `/proc/<pid>/exe` inode; macOS adds the
running-process CDHash). Production installs still need a trusted install path
or verified Homebrew/tarball installation before `cloakd` starts.

The accept-loop wires this to dispatch at
`crates/cloak-core/src/daemon.rs:235-292`: peer-auth runs, the connection
either gets a `conn_id` and proceeds to the request loop or is closed
without a write.

### Session lifecycle

`crates/cloak-core/src/session.rs` issues a 32-byte random token,
base64url-encoded, on the first `*.handshake`. Tokens carry a 30-minute TTL
(`session::default_ttl()`), are bound to the connection's `conn_id`, and are
compared with `subtle::ConstantTimeEq::ct_eq`
(`crates/cloak-core/src/session.rs:124`). When the connection closes, every
session token bound to that `conn_id` is revoked
(`crates/cloak-core/src/daemon.rs:289-291`).

## Storage layout

A single SQLite database at `~/Library/Application Support/cloak/vault.cloak`
on macOS (XDG-equivalent on Linux). WAL journal mode, `synchronous = NORMAL`,
all tables `STRICT`. Migrations are forward-only and recorded in
`schema_migrations` (`crates/cloak-core/src/store.rs:20-21`,
`crates/cloak-core/migrations/0001_init.sql`).

```
+----------------------+        +------------------------------+
|  meta (id = 1)       |        |  secrets                     |
+----------------------+        +------------------------------+
|  format_version      |        |  id            (rowid)       |
|  salt (16 B)         |        |  name          (UNIQUE)      |
|  kdf_phc (PHC str)   |        |  kind                        |
|  wrap_nonce (24 B)   |        |  tags          (JSON array)  |
|  wrap_aead           |        |  created_at                  |
|  monotonic_counter   |        |  updated_at                  |
|  created_at          |        |  version       (monotonic)   |
+----------------------+        |  nonce         (24 B)        |
                                |  ciphertext    (ct || tag)   |
                                +------------------------------+
```

### Master key wrap

The vault master key is generated once at `init`, stays in `cloakd` memory
while the vault is unlocked, and is **never** persisted in plaintext.

1. **Pepper** comes from the OS keychain - macOS Keychain generic-password
   storage or freedesktop Secret Service / GNOME Keyring on Linux.
   `CLOAK_PEPPER_FILE` is a 0600-only escape hatch for CI and headless
   servers (`crates/cloak-core/src/keychain.rs`). v1.0 does not install a
   custom per-process/code-signature ACL for the pepper; the pepper is a
   defense against vault-file-only theft, not against a same-user process that
   can satisfy the OS keychain access policy.
2. **`wrap_key = Argon2id(HMAC-SHA256(pepper, passphrase), salt, params)`**
   - keyed-mode KDF, autotuned to ≤500 ms at `init`. The pepper raises the
   bar for an offline attacker who has only the vault file.
   (`crates/cloak-core/src/crypto.rs:366-381`)
3. **`wrap_aead = XChaCha20-Poly1305-IETF(wrap_key, wrap_nonce, master, AAD = b"cloak.master.v1")`**
   - versioned AAD so a future v2 wrap scheme will not collide with v1.
   (`crates/cloak-core/src/vault.rs:40,210,246`)

### Per-record subkeys and AAD

Each `secrets` row carries its own AEAD nonce and ciphertext. The per-record
key is **not** the master key - it is derived per-rowid:

```
record_key = crypto_kdf_derive_from_key(master, record_id, b"cloakrec")
```

(`crates/cloak-core/src/crypto.rs:533-542`,
`crates/cloak-core/src/vault.rs:42-43`)

The AAD bound to each record's ciphertext is built canonically as

```
name_len_be(u32) || name_utf8 || created_unix_be(i64) || version_be(u64)
```

(`crates/cloak-core/src/vault.rs:414-426`). This binds the record's identity
to the ciphertext, so a row's ciphertext cannot be swapped under another
row's name (verified by
`vault::tests::aad_swap_attack_fails`).

### Rollback resistance

The `meta.monotonic_counter` lives in the vault file *and* is mirrored
into a separate OS-keychain item (`dev.cloak` / `vault.rollback-counter.v1`)
alongside a SHA-256 commitment to the logical vault state. Every write
enforces strict increase via `bump_counter` and updates the out-of-band
mirror before the SQLite transaction commits, so a thief who restores
`vault.cloak` from a stale backup hits `Error::VaultRollbackDetected`
*on open*, before any record is decrypted. The state commitment prevents
the old snapshot from being accepted merely by editing its plaintext
counter up to the current mirror value.

The check follows three rules: file state == mirror state is a no-op;
any mismatch after a mirror exists is rejected; a missing mirror (fresh
install or upgrade from a Cloak that didn't have the mirror) is seeded
from the file on first open. Pre-1.0.2 counter-only mirrors fail closed
until an operator explicitly runs `cloak rollback adopt-state --yes` after
reviewing the current vault file; the old counter-only mirror cannot prove
pre-upgrade history. With `CLOAK_PEPPER_FILE` set the
mirror falls back to a 0600 file alongside the pepper; in that fallback
an attacker who can roll back the vault can also roll back the counter
file in lockstep - see `docs/THREAT_MODEL.md`.

## Privileged tool dispatch

Every privileged tool handler in `crates/cloak-core/src/handlers.rs`
follows the same ordered recipe (`crates/cloak-core/src/handlers.rs:1-22`):

1. Parse + validate parameters (typed, no free-form JSON).
2. Resolve the policy `EvalContext` from `(tool, secret_name, secret_kind,
   target_host, peer_basename)`.
3. Run the policy gate. On `Action::Deny` or `RequireConfirmation`,
   audit a `Denied` entry and return `Error::PolicyDenied` - **never**
   touching the vault. `RequireConfirmation` is parsed today but fails
   closed; there is no confirmation side-channel yet.
4. Run the rate-limit gate (token bucket per `(tool, peer, secret)`).
   On exhaustion, audit `Denied` and return `Error::PolicyDenied("rate limited")`.
5. Only now read the secret from the unlocked vault.
6. For side-effecting network tools (`proxy_http`, AWS STS token minting),
   append a durable `Started` audit entry before making the outbound request.
7. Perform the operation, audit `Ok` (or `Error` on a downstream failure),
   and return.

The order is load-bearing: a denied call cannot decrypt
(`crates/cloak-core/src/handlers.rs:109-185`).

## Outbound HTTP

Network egress is daemon-owned and limited to explicit tool calls. The MCP shim
imports zero HTTP clients - `packages/cloak-mcp/scripts/check-no-http.mjs`
(invoked by `bun run lint:no-http`) fails CI on regression.

`tool.proxy_http` uses `crates/cloak-core/src/egress.rs` with reqwest, rustls,
the system root store, redirects disabled, and a 30-second total timeout.
`egress.rs` also carries an SSRF backstop: it refuses to connect to any
non-global IP address (loopback, private, link-local incl. the cloud-metadata
`169.254.169.254`, ULA, etc.) for both IP-literal hosts and hostnames. The
hostname check runs in a custom DNS resolver whose vetted addresses are exactly
the ones reqwest connects to, so DNS-rebinding on an allowlisted name cannot
reach a private address. This is independent of, and in addition to, the
`allowed_hosts` policy glob. `tool.mint_token` uses the AWS Smithy STS client in
`crates/cloak-core/src/handlers.rs`, also bounded by a daemon-side 30-second
timeout. Host allowlists apply to proxy requests; STS minting is gated by
tool/secret policy instead of an arbitrary destination allowlist.

`tool.proxy_http` enforces `policy.toml::allowed_hosts` before issuing the
request. The auth header is attached by the daemon and is not returned as
request metadata. The upstream response status, headers, and body are returned
to the MCP client; Cloak does not redact arbitrary response content
(`crates/cloak-core/src/handlers.rs`).

## Audit log

Append-only JSONL at `<data_dir>/cloak/audit.jsonl`. Denied calls write a
`Denied` entry; privileged side-effecting calls write `Started` before the
risky operation and then `Ok` or `Error`. The chain hash is `SHA-256` over
the RFC 8785 canonical-JSON serialization of the previous entry;
`prev_hash[0]` is `"0".repeat(64)`
(`crates/cloak-core/src/audit.rs:1-186`).

`cloak audit verify` recomputes the chain from disk and rejects any mutated,
deleted, or reordered line (`crates/cloak-core/src/audit.rs:188-220`).
Concurrent appends are gated by an `fs2` exclusive `flock` and an `fsync`
on every write
(`crates/cloak-core/src/audit.rs::tests::concurrent_appends_are_atomic_and_complete`).
The tail head is also anchored outside the log; a non-empty legacy log with
no anchor fails closed until an operator explicitly runs
`cloak audit adopt-head --yes` after reviewing the existing chain.

## Repository map

```
crates/cloak-core/
├── src/
│   ├── crypto.rs       libsodium FFI; Secret<T>; AEAD; Argon2id; subkey KDF
│   ├── vault.rs        Vault open/unlock/add/set/show; AAD construction
│   ├── store.rs        SQLite WAL + STRICT tables + migrations
│   ├── keychain.rs     macOS Keychain / Linux Secret Service / pepper file
│   ├── ipc.rs          length-prefixed JSON framing; Error → RpcError
│   ├── peer_auth.rs    SOL_LOCAL/LOCAL_PEERTOKEN, SO_PEERCRED/SO_PEERPIDFD, peer hash allowlist
│   ├── session.rs      tokens; ConstantTimeEq compare; revoke_by_conn
│   ├── daemon.rs       accept loop; dispatcher; CLI-only gate
│   ├── handlers.rs     privileged tool handlers (sign, proxy, mint, audit)
│   ├── policy.rs       TOML DSL; rate-limit buckets; EvalContext
│   ├── audit.rs        hash-chained JSONL; verify()
│   ├── egress.rs       reqwest + rustls HTTP client
│   └── error.rs        typed errors (mapped to RpcError on the wire)
├── migrations/0001_init.sql
└── tests/              ipc_e2e.rs, handlers_e2e.rs

crates/cloak-cli/
└── src/commands/       init, add, set, get, list, rm, show, status,
                        completions, unlock/daemon-unlock, daemon,
                        audit, backup, restore

packages/cloak-mcp/
└── src/
    ├── server.ts       MCP transport; the only entry point
    ├── ipc.ts          length-prefixed JSON client
    └── tools/          one file per tool (zod schema + dispatch)
```

## Cross-references

- Wire contract: `docs/IPC_WIRE.md`
- Threat model: `docs/THREAT_MODEL.md`
- Tool spec (JSON Schema, descriptions, examples): `docs/spec/mcp-tools.md`
- Security invariants (file:line, test, CI gate): `docs/SECURITY_INVARIANTS.md`
- Release verification (cosign + slsa-verifier): `docs/RELEASE.md`
