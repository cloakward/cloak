# Cloak

> An MCP-native secrets vault for Claude Desktop and Claude Code.

Cloak replaces the prevailing anti-pattern of pasting API keys into prompts (or shoving them into `.env` files that LLMs cheerfully read into context) with a hardened local daemon that **never exposes raw secret material to the model**.

Agents call action-shaped MCP tools — `sign_request`, `proxy_authenticated_http_request`, `mint_short_lived_token` — and the daemon performs the privileged operation on the agent's behalf. Reveal is a deliberate, biometric-gated CLI act, not a tool call.

This drop is **v0.1**, completed in ~2 days against an 8-week original spec (see `BUILD_PLAN.md` in `compass_artifact_*.md`). The load-bearing security invariants are intact; the operational scaffolding (cross-platform CI matrix, signed releases, recovery, rotation handlers) is deferred.

---

## Status: 147 tests passing, end-to-end smoke test green

```
cloak-core unit + property                 114
cloak-core ipc_e2e (integration)             2
cloak-core handlers_e2e (integration)        6
cloak-cli (assert_cmd + insta snapshot)     12
cloak-mcp (Bun test, IPC + tools + grep)    13
                                          ----
                                           147
```

Plus `scripts/smoke-test.sh` exercises the full real flow: build → daemon up → `cloak init/add/list/show` round-trip → `cloak daemon-unlock` over IPC → `cloak-mcp --self-test` (handshake + `vault.list`) → audit log tail.

---

## Architecture

```
              ┌──────────────────┐         ┌──────────────────┐
              │  Claude Desktop  │         │     terminal     │
              │  / Claude Code   │         │       user       │
              └────────┬─────────┘         └────────┬─────────┘
                       │ MCP / stdio                │ exec
                       ▼                            ▼
              ┌──────────────────┐         ┌──────────────────┐
              │    cloak-mcp     │         │      cloak       │
              │   (Bun, TS)      │         │      (Rust)      │
              │  zero HTTP imps  │         │   library + IPC  │
              └────────┬─────────┘         └────────┬─────────┘
                       │ length-prefixed JSON over UDS, peer-auth'd
                       ▼                            ▼
                              ┌─────────────────┐
                              │     cloakd      │
                              │     (Rust)      │
                              │ • libsodium     │
                              │ • SQLite WAL    │
                              │ • policy + audit│
                              │ • reqwest+rustls│
                              └────────┬────────┘
                                       │
                                       ▼  AEAD-sealed records
                              ┌─────────────────┐
                              │   vault.cloak   │
                              └─────────────────┘
```

Three processes, one trust boundary. The MCP shim translates MCP tool calls to IPC requests; it imports zero HTTP clients (CI grep gate enforces). The daemon owns the vault, the policy, the audit log, and **all** outbound HTTP. The CLI reads/writes the vault file directly today (v0.1) and pushes the in-memory unlock state to the daemon via `cloak daemon-unlock`. v1.x will move the CLI fully onto IPC.

---

## Quickstart (macOS)

```sh
# 0. One-time setup. libsodium is required.
brew install libsodium bun

# 1. Build everything. ~50s on a recent M-class Mac.
cargo build --release --workspace
cd packages/cloak-mcp && bun install && bun build src/server.ts --compile --outfile dist/cloak-mcp && cd ../..

# 2. Initialize the vault. Argon2id autotunes (≤500ms target).
./target/release/cloak init

# 3. Add a secret. The value is read with echo OFF.
./target/release/cloak add OPENAI_API_KEY

# 4. Run the daemon (foreground for now; a launchd plist is in scripts/).
./target/release/cloakd &

# 5. Unlock the daemon's in-memory vault state.
./target/release/cloak daemon-unlock

# 6. Wire into Claude Desktop:
# Add to ~/Library/Application Support/Claude/claude_desktop_config.json:
# {
#   "mcpServers": {
#     "cloak": { "command": "/abs/path/to/packages/cloak-mcp/dist/cloak-mcp" }
#   }
# }

# 7. Self-test: handshake + vault.list end-to-end.
./packages/cloak-mcp/dist/cloak-mcp --self-test    # → "ok"
```

For a fully automated end-to-end demo run `./scripts/smoke-test.sh` — it does all of the above against a hermetic temp `HOME`.

---

## What's in v0.1

### Implemented
- **Crypto:** libsodium-only via `libsodium-sys-stable`. XChaCha20-Poly1305-IETF AEAD; Argon2id keyed mode with autotune (HMAC-SHA256(pepper, passphrase) → `crypto_pwhash`); per-record subkeys via `crypto_kdf_derive_from_key`. `Secret<T>` zeroize-on-drop everywhere.
- **Vault:** SQLite WAL, STRICT tables, master-key wrapping with AAD `cloak.master.v1`, per-record AAD binding `(name || created_unix || version)`. Monotonic counter rejects rollback. macOS Keychain pepper or `CLOAK_PEPPER_FILE` fallback.
- **CLI:** `init`, `add`, `set`, `get`, `list`, `rm`, `show` (Touch ID gated, TTY-only), `status`, `completions`, `daemon-unlock`. `CLOAK_PASSPHRASE` test-only escape hatch with stderr warning.
- **Daemon (`cloakd`):** Tokio UDS listener with mode 0600, peer-credential auth (`SOL_LOCAL`/`LOCAL_PEERPID` + `getpeereid` on macOS, `SO_PEERCRED` on Linux) and SHA-256 of the peer binary as a v0.1 code-signature surrogate, session tokens bound to (peer_pid, basename, conn_id) with constant-time compare, signal-driven graceful shutdown, stale-socket cleanup with probe-connect.
- **IPC:** length-prefixed JSON, 4 MiB cap, typed error code map (`peer-not-trusted`, `vault-locked`, `policy-denied`, `aead-failure`, `audit-broken`, etc.).
- **MCP server:** Bun-compiled single binary speaking the official `@modelcontextprotocol/sdk`, six action-shaped tools, zod-validated args, **zero outbound HTTP** (`scripts/check-no-http.mjs` grep gate enforces).
- **Privileged handlers:** `tool.sign_request` (HMAC-SHA256 + AWS SigV4 *stub*), `tool.proxy_http` (reqwest+rustls + allowed-hosts + auth-header strip), `tool.mint_token` (AWS STS *stub*), `tool.query_audit`. Policy is checked **before** vault read — denied calls never decrypt.
- **Audit log:** hash-chained JSONL (RFC 8785 canonical JSON, SHA-256 chain), atomic append (fs2 exclusive flock + fsync), `verify` rejects mutated/deleted/reordered lines. 4-thread concurrent-append test green.
- **Policy:** TOML DSL with default-deny, per-secret rules, glob matching (most-specific wins), `allowed_hosts`, token-bucket rate limiter per (tool, peer, secret).
- **Tests:** 147 passing across Rust and TypeScript. End-to-end smoke script. Constant-time compare for session tokens. Property tests on AEAD round-trip + tamper detection.

### Stubbed for v1.0 (documented in CHANGELOG)
- AWS SigV4 returns SigV4-shaped headers but uses HMAC-SHA256 internally rather than the real algorithm (`X-Cloak-Sigv4-Stub: 1` marker). Pulling `aws-sigv4` + `aws-smithy-*` was deferred to keep the dep surface small.
- `tool.mint_token aws-sts` returns `cloak-stub-sts-<uuid>` placeholders rather than calling real STS. Real `aws-sdk-sts` integration is v1.0 work.
- `mint_token` for `github-app` / `gitlab-pat` returns a typed not-supported error (still audited).

### Deferred from the 8-week plan
- Cross-platform CI matrix beyond macOS arm64 (in flight; v1.0 ships **macOS + Linux only — Windows lands in v1.0.1**, see [issue #2](https://github.com/cloakward/cloak/issues/2)).
- Linux Keychain (Secret Service) and biometric (polkit) are stubs in v0.1.
- SLSA L3 / cosign signed releases. SignPath OV signing (Windows) is v1.0.1 ([issue #3](https://github.com/cloakward/cloak/issues/3)).
- BIP-39 24-word recovery, `cloak export/import`, `.env` import, `cloak rotate NAME`.
- Mintlify docs site, fuzz harnesses, full property-test KAT vector suite, chaos tests.
- `cargo deny` / `cargo audit` policy enforcement in CI.

The full inventory of what's in vs. out is in `CHANGELOG.md`.

---

## Repository layout

```
.
├── BUILD_PLAN.md                 ← inside compass_artifact_*.md
├── README.md                     (this file)
├── CHANGELOG.md
├── SECURITY.md
├── Cargo.toml
├── rust-toolchain.toml
├── crates/
│   ├── cloak-core/               libsodium / vault / store / daemon / IPC / audit / policy / handlers
│   │   ├── src/
│   │   ├── migrations/
│   │   └── tests/                ipc_e2e.rs, handlers_e2e.rs
│   └── cloak-cli/                clap CLI + Touch ID + IPC client
│       ├── src/commands/
│       └── tests/cli.rs
├── packages/
│   └── cloak-mcp/                Bun MCP server, tools/, ipc.ts, server.ts, tests/
├── docs/
│   ├── IPC_WIRE.md               frozen wire-format contract
│   ├── THREAT_MODEL.md           assets, adversaries, residual risks
│   └── QUICKSTART.md
└── scripts/
    ├── smoke-test.sh             end-to-end real-binary smoke test
    ├── policy.example.toml       default-deny TOML policy
    ├── dev.cloak.cloakd.plist    launchd template
    └── install-launchd.sh
```

---

## Security invariants (load-bearing)

These are enforced by code and CI; they are NOT aspirational:

1. **No MCP tool returns plaintext secret material.** A property test asserts. The MCP surface contains zero `get_secret` / `reveal_secret` / `read_secret` methods.
2. **The daemon owns all outbound HTTP.** `cloak-mcp` has zero HTTP imports; `scripts/check-no-http.mjs` grep gate fails CI on regression.
3. **Peer auth runs before any session token issuance.** A connection from a binary not on the allowlist is dropped before the daemon writes anything to it.
4. **Policy is checked before vault read.** A denied tool call never decrypts the secret; an audit entry is written with `result: "denied"`.
5. **libsodium only, no rolling our own.** Argon2id keyed mode for KDF; XChaCha20-Poly1305-IETF for AEAD; `crypto_kdf_derive_from_key` for per-record subkeys; `randombytes_buf` for nonces. SHA-256 (`sha2` crate) is used **only** for the audit hash chain and code-sig digests, never as a primitive in the secret-protection path.
6. **`Secret<T>` zeroize-on-drop everywhere.** `Debug` redacts to `"***"`. The accessor is `expose_secret()` — grep-able for review.

See `docs/THREAT_MODEL.md` for the full adversary model and `docs/IPC_WIRE.md` for the frozen wire contract.

---

## A note on macOS Gatekeeper

Cloak v1.0 binaries are not Apple-notarized. If you download a release artifact (rather than building from source), macOS Gatekeeper will block it until you clear the quarantine attribute:

```sh
xattr -d com.apple.quarantine ./cloak ./cloakd ./cloak-mcp
```

Every release is cosign-signed with SLSA L3 provenance, which lets you verify the binary is the exact artifact CI built. Notarization adds Apple's pre-execution scan on top and is a v1.x deliverable. See `docs/QUICKSTART.md` for the full Gatekeeper walkthrough.

## License

Apache-2.0.
