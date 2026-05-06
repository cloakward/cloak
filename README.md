# Cloak

> An MCP-native secrets vault for Claude Desktop and Claude Code.

Cloak replaces the prevailing anti-pattern of pasting API keys into prompts (or shoving them into `.env` files that LLMs cheerfully read into context) with a hardened local daemon that **never exposes raw secret material to the model**.

Agents call action-shaped MCP tools — `sign_request`, `proxy_authenticated_http_request`, `mint_short_lived_token` — and the daemon performs the privileged operation on the agent's behalf. Reveal is a deliberate, biometric-gated CLI act, not a tool call.

This drop is **v0.9.0-rc1**, the first release candidate for v1.0: the load-bearing security invariants are intact, the post-v0.1 work has landed (real AWS SigV4/STS, Linux Secret Service pepper, cross-platform CI matrix, cosign-signed SLSA L3 releases), and Windows + biometric polkit + recovery + rotation handlers are scoped to v1.0.1 / v1.x.

---

## Status: 149 tests passing, end-to-end smoke test green

```
cloak-core unit + property                 115
cloak-core ipc_e2e (integration)             2
cloak-core handlers_e2e (integration)        7
cloak-cli (assert_cmd + insta snapshot)     12
cloak-mcp (Bun test, IPC + tools + grep)    13
                                          ----
                                           149
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

Three processes, one trust boundary. The MCP shim translates MCP tool calls to IPC requests; it imports zero HTTP clients (CI grep gate enforces). The daemon owns the vault, the policy, the audit log, and **all** outbound HTTP. The CLI reads/writes the vault file directly today (v0.9.x) and pushes the in-memory unlock state to the daemon via `cloak daemon-unlock`. v1.x will move the CLI fully onto IPC.

---

## Install for Claude Desktop (no terminal)

If you only want to use Cloak inside Claude Desktop and would rather skip the build steps below:

1. Download `Cloak-0.9.0-rc1-<your-platform>.dxt` from the [latest release](https://github.com/cloakward/cloak/releases).
2. Drag the `.dxt` onto Claude Desktop's **Settings → Extensions** panel (or double-click it).
3. On first activation, Cloak's setup wizard runs in a native dialog — it walks you through vault init, daemon launch, and the biometric / passphrase prompts. No terminal commands required.

The `.dxt` bundles only the `cloak-mcp` shim. The privileged `cloak` CLI + `cloakd` daemon ship via Homebrew / `.deb` / install script — the wizard checks for them and points you at <https://cloakward.dev/install> if they're missing. Windows `.dxt` is deferred to v1.0.1.

For everything else (development, server-side install, custom policy), use the quickstart below.

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
```

> **⚠️ Back up your passphrase before adding any secret.** Cloak v0.9.0-rc1 has no recovery mechanism: if you lose your passphrase, every secret in the vault is permanently unrecoverable. Store it in a password manager or out-of-band backup. BIP-39 24-word recovery is planned for v1.x.

```sh
# 3. Add a secret. The value is read with echo OFF.
./target/release/cloak add OPENAI_API_KEY

# 4. Run the daemon (foreground for now; a launchd plist is in scripts/).
./target/release/cloakd &

# 5. Unlock the daemon's in-memory vault state.
./target/release/cloak daemon-unlock
```

> Note: re-run `cloak daemon-unlock` after every reboot, daemon restart, or launchd respawn — `cloakd` holds the master key only in memory.

```sh
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

## What's in v0.9.0-rc1 (release-candidate scope for v1.0)

### Implemented
- **Crypto:** libsodium-only via `libsodium-sys-stable`. XChaCha20-Poly1305-IETF AEAD; Argon2id keyed mode with autotune (HMAC-SHA256(pepper, passphrase) → `crypto_pwhash`); per-record subkeys via `crypto_kdf_derive_from_key`. `Secret<T>` zeroize-on-drop everywhere.
- **Vault:** SQLite WAL, STRICT tables, master-key wrapping with AAD `cloak.master.v1`, per-record AAD binding `(name || created_unix || version)`. Monotonic counter rejects rollback. macOS Keychain pepper, freedesktop Secret Service on Linux (W7), or `CLOAK_PEPPER_FILE` fallback.
- **CLI:** `init`, `add`, `set`, `get`, `list`, `rm`, `show` (Touch ID gated, TTY-only), `status`, `completions`, `daemon-unlock`. `CLOAK_PASSPHRASE` test-only escape hatch with stderr warning.
- **Daemon (`cloakd`):** Tokio UDS listener with mode 0600, peer-credential auth (`SOL_LOCAL`/`LOCAL_PEERPID` + `getpeereid` on macOS, `SO_PEERCRED` on Linux) and SHA-256 of the peer binary recorded as a code-signature audit field (true mach-o code-directory matching is a v1.0.1 deliverable), session tokens bound to (peer_pid, basename, conn_id) with constant-time compare, signal-driven graceful shutdown, stale-socket cleanup with probe-connect.
- **IPC:** length-prefixed JSON, 4 MiB cap, typed error code map (`peer-not-trusted`, `vault-locked`, `policy-denied`, `aead-failure`, `audit-broken`, etc.).
- **MCP server:** Bun-compiled single binary speaking the official `@modelcontextprotocol/sdk`, six action-shaped tools, zod-validated args, **zero outbound HTTP** (`packages/cloak-mcp/scripts/check-no-http.mjs` grep gate enforces).
- **Privileged handlers:** `tool.sign_request` (HMAC-SHA256 + real AWS SigV4 via `aws-sigv4`, KAT-verified), `tool.proxy_http` (reqwest+rustls + allowed-hosts + auth-header strip), `tool.mint_token` (real AWS STS via `aws-sdk-sts`), `tool.query_audit`. Policy is checked **before** vault read — denied calls never decrypt.
- **Audit log:** hash-chained JSONL (RFC 8785 canonical JSON, SHA-256 chain), atomic append (fs2 exclusive flock + fsync), `verify` rejects mutated/deleted/reordered lines. 4-thread concurrent-append test green.
- **Policy:** TOML DSL with default-deny, per-secret rules, glob matching (most-specific wins), `allowed_hosts`, token-bucket rate limiter per (tool, peer, secret).
- **Tests:** 149 passing across Rust and TypeScript. End-to-end smoke script. Constant-time compare for session tokens. Property tests on AEAD round-trip + tamper detection.

### Real, no longer stubbed (post-v0.1, W1)
- `tool.sign_request scheme=aws-sigv4` produces an AWS-accepted SigV4 signature via `aws-sigv4`, KAT-verified against the published `get-vanilla` test vector.
- `tool.mint_token kind=aws-sts` calls real `GetSessionToken` via `aws-sdk-sts` (rustls/ring; `aws-lc-rs` excluded from the daemon dependency graph).
- `mint_token` for `github-app` / `gitlab-pat` still returns a typed not-supported error (still audited).

### Deferred from the 8-week plan
- Linux desktop pepper now uses freedesktop Secret Service (W7); Linux biometric is enforced via polkit (action `dev.cloak.show-secret`, see `scripts/polkit/dev.cloak.policy`).
- v0.9.0-rc1 ships **macOS + Linux only — Windows lands in v1.0.1**, see [issue #2](https://github.com/cloakward/cloak/issues/2).
- Cosign keyless + SLSA L3 provenance ship in v0.9.0-rc1 (W9b). SignPath OV signing (Windows) is v1.0.1 ([issue #3](https://github.com/cloakward/cloak/issues/3)).
- Apple notarization is a v1.x deliverable (see "macOS Gatekeeper" below and `docs/QUICKSTART.md`).
- BIP-39 24-word recovery, `cloak export/import`, `.env` import, `cloak rotate NAME`.
- Mintlify docs site, fuzz harnesses, full property-test KAT vector suite, chaos tests.

The full inventory of what's in vs. out is in `CHANGELOG.md`.

---

## Repository layout

```
.
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
│   ├── ARCHITECTURE.md           three-process model, IPC, storage layout
│   ├── IPC_WIRE.md               frozen wire-format contract
│   ├── THREAT_MODEL.md           assets, adversaries, residual risks
│   ├── SECURITY_INVARIANTS.md    file:line / test / CI-gate per invariant
│   ├── RELEASE.md                cutting and verifying a release
│   ├── spec/mcp-tools.md         JSON Schema spec for the six MCP tools
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
2. **The daemon owns all outbound HTTP.** `cloak-mcp` has zero HTTP imports; `packages/cloak-mcp/scripts/check-no-http.mjs` grep gate fails CI on regression.
3. **Peer auth runs before any session token issuance.** A connection from a binary not on the allowlist is dropped before the daemon writes anything to it.
4. **Policy is checked before vault read.** A denied tool call never decrypts the secret; an audit entry is written with `result: "denied"`.
5. **libsodium only, no rolling our own.** Argon2id keyed mode for KDF; XChaCha20-Poly1305-IETF for AEAD; `crypto_kdf_derive_from_key` for per-record subkeys; `randombytes_buf` for nonces. SHA-256 (`sha2` crate) is used **only** for the audit hash chain and code-sig digests, never as a primitive in the secret-protection path.
6. **`Secret<T>` zeroize-on-drop everywhere.** `Debug` redacts to `"***"`. The accessor is `expose_secret()` — grep-able for review.

See `docs/THREAT_MODEL.md` for the full adversary model, `docs/IPC_WIRE.md` for the frozen wire contract, `docs/ARCHITECTURE.md` for the three-process layout, `docs/spec/mcp-tools.md` for the locked tool schemas, and `docs/SECURITY_INVARIANTS.md` for the file:line backing of each invariant.

---

## A note on macOS Gatekeeper

v0.9.0-rc1 (and v1.0 going forward) binaries are not Apple-notarized. If you download a release artifact (rather than building from source), macOS Gatekeeper will block it until you clear the quarantine attribute:

```sh
xattr -d com.apple.quarantine ./cloak ./cloakd ./cloak-mcp
```

Every release is cosign-signed with SLSA L3 provenance, which lets you verify the binary is the exact artifact CI built. Notarization adds Apple's pre-execution scan on top and is a v1.x deliverable. See `docs/QUICKSTART.md` for the full Gatekeeper walkthrough.

## License

Apache-2.0.
