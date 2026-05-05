# Changelog

All notable changes to Cloak. Format follows Keep-a-Changelog; we use SemVer.

## [Unreleased]

### Added
- v0.1 source drop:
  - Cargo workspace with `cloak-core` library + `cloakd` daemon binary; `cloak-cli` binary.
  - libsodium-backed crypto: XChaCha20-Poly1305-IETF AEAD, Argon2id keyed KDF with autotune, `Secret<T>` zeroize-on-drop.
  - SQLite WAL vault with STRICT tables, monotonic rollback counter, macOS Keychain pepper.
  - CLI commands: `init`, `add`, `set`, `get`, `list`, `rm`, `show`, `status`. Touch ID gate on `show`.
  - UDS IPC + length-prefixed JSON framing + peer-credential auth (PID + code-signature) + session tokens.
  - Bun-compiled MCP server with six action-shaped tools; zero outbound HTTP.
  - Hash-chained JSONL audit log with `cloak audit verify`.
  - TOML policy DSL with default-deny, allowed_hosts, rate limit, require_confirmation.
  - `tool.sign_request` (HMAC-SHA256, AWS SigV4), `tool.proxy_http` (reqwest+rustls + allowlist), `tool.mint_token` (AWS STS), `tool.query_audit`.
- Privileged tool handlers wired end-to-end through the daemon:
  - `tool.sign_request` — HMAC-SHA256 over `"{METHOD}\n{URL}\n{sha256_hex(body)}\n"`, returning only `X-Cloak-Signature`.
  - `tool.proxy_http` — strips caller-supplied `Authorization`/`Cookie`/`X-Api-Key`, attaches auth via bearer/basic/header/query, never echoes the auth header back.
  - `tool.mint_token` — `aws-sts` kind calls real STS `GetSessionToken` (post-W1) and returns a base64'd JSON envelope of the temporary credentials with RFC3339 `expires_at`; other kinds return a typed not-supported error (still audited).
  - `tool.query_audit` — filters audit entries by time/tool/secret/result/limit; never returns secret values.
- `crates/cloak-core/src/egress.rs` — single workspace outbound-HTTP module. `reqwest` with rustls TLS, 3-redirect cap, 30s timeout. `cloak-mcp` remains HTTP-free.
- `HandlerCtx` bundles vault / policy / audit / egress / peer for every privileged tool call. The daemon dispatcher builds it per-call and passes it down.
- Daemon now resolves a default policy at `~/.config/cloak/policy.toml` (missing file ⇒ default-deny) and a default audit log at `<data_dir>/cloak/audit.jsonl`. Test entry `daemon::run_with` accepts explicit `policy_path` and `audit_path` parameters.

### Security
- No tool returns plaintext secret material — property test asserts.
- Daemon owns all outbound HTTP; MCP shim has zero HTTP imports — CI grep enforces.
- Peer auth runs *before* any session token issuance.
- Policy is checked **before** vault read for every privileged tool call — a denied call never decrypts the secret.
- Every privileged tool call writes exactly one audit entry (`Ok` / `Denied` / `Error`).

### Added (post-v0.1, W1, decision: option A)
- Replaced the v0.1 SigV4 + STS stubs with real `aws-sigv4` + `aws-sdk-sts` (rustls/ring; `aws-lc-rs` hard-excluded from the daemon dependency graph). `tool.sign_request scheme=aws-sigv4` now produces an AWS-accepted SigV4 signature, KAT-verified against the published `get-vanilla` test vector. `tool.mint_token kind=aws-sts` calls real `GetSessionToken`. Wire shapes unchanged. Secret format remains `<access_key_id>:<secret_access_key>`.

### Deferred / stubbed
- `github-app` / `gitlab-pat` mint kinds are not implemented in v0.1; they pass policy + rate limit, then return a typed not-supported error and are audited.

### Deferred from 8-week plan
- Cross-platform: Linux/Windows compile but Keychain/biometric/peer-auth are stubs.
- Signed releases (SLSA L3 / cosign / SignPath) — dev builds only in v0.1.
- BIP-39 24-word recovery, `.env` import, GitHub App / GitLab PAT rotation handlers.
- Mintlify docs site, fuzz harnesses, full property-test KAT vector suite, chaos tests.

### Operational additions on top of the 8-week scope
- `CLOAK_PEPPER_FILE` env override for environments where the OS keychain is unavailable (CI runners, headless servers, sandboxed dev). File is enforced 0600; world/group readable refuses to load. Documented as a residual risk in `THREAT_MODEL.md`.
- `cloak daemon-unlock` — a CLI bridge that pushes the vault passphrase to a running `cloakd` over IPC so MCP peers can serve requests in v0.1 (where the CLI is library-direct rather than an IPC client). v1.x absorbs this into `cloak unlock` once the CLI moves fully onto IPC.
- `scripts/smoke-test.sh` — end-to-end real-binary verification: builds release artifacts, hermetic HOME, init/add/list/show round-trip, daemon up, daemon-unlock over IPC, MCP `--self-test`. Green on macOS arm64.

### Test counts (v0.1)
- 114 cloak-core unit + property tests
- 2 cloak-core ipc_e2e integration tests
- 6 cloak-core handlers_e2e integration tests
- 12 cloak-cli assert_cmd + insta snapshot tests
- 13 cloak-mcp Bun tests (IPC framing, tool dispatch, no-HTTP grep gate, plaintext-leak guard)
- **147 total**, all green; `cargo clippy --workspace --all-targets -- -D warnings` clean.
