# Changelog

All notable changes to Cloak. Format follows Keep-a-Changelog; we use SemVer.

## [Unreleased]

### Added
- release tarballs include cloak-mcp at bin/cloak-mcp on macOS arm64, macOS x64, and Linux gnu amd64; brew/curl installs ship all three binaries with no npm dependency. (Linux musl + Linux arm64 ship cloak + cloakd only because bun --compile can't cross-target those triples — track in a follow-up issue if needed.)
- `Cloak.dxt` extension for Claude Desktop — drag-and-drop install, native setup dialogs. Bundles `cloak-mcp` and runs `cloak setup` via OS-native dialog flow on first activation (no terminal commands required). One `.dxt` per platform (macOS arm64/x64, Linux x64/arm64) ships with the GitHub release. Windows `.dxt` deferred to v1.0.1.

### Fixed (release-engineering follow-ups, post-tag)
- `release.yml` verify job now downloads the `signed-bundle` and SLSA provenance artifacts via `actions/download-artifact` instead of `gh release download`, because `gh release download` cannot see DRAFT releases (and the workflow design keeps the release in DRAFT until verify passes). The bytes verified are identical to those uploaded to the draft.
- `release.yml` `gh release create` now passes `--prerelease` whenever the tag matches `-rc*|-beta*|-alpha*|-pre*|-dev*`, so downstream workflows can gate production-only side-effects on the release event's `prerelease` flag.
- `docker-push.yml` no longer pushes `:latest` for pre-release tags. `:VERSION` and `:MAJOR_MINOR` always go; `:latest` is appended only when the tag is not a pre-release (derived from the tag-name pattern so it works on both `release.published` and `workflow_dispatch`).
- `release.yml` SLSA-provenance download steps now hard-code the artifact name `multiple.intoto.jsonl` rather than reading it from `${{ needs.provenance.outputs.provenance-name }}`, defending against a historical SLSA-reusable-workflow footgun where that output is intermittently empty.
- `packages/cloak-mcp/package.json` adds `repository`, `homepage`, `bugs`, and `publishConfig` (no provenance) fields, plus a `files` allowlist so the published tarball is ~30 KB instead of 192 MB.
- `npm-publish.yml` triggers the NPM_TOKEN fallback on 404 (not just 403), the response code for the very first publish of a brand-new scoped package; adds `workflow_dispatch` for manual re-runs.
- `Dockerfile` cache mounts use `sharing=locked` on a single shared cargo cache. An earlier attempt to partition by `id=cargo-{registry,target}-${TARGETARCH}` cleared the EEXIST race between the linux/amd64 and linux/arm64 buildx invocations but somehow interfered with rustc's discovery of the target std libs (`error[E0463]: can't find crate for core`); locked sharing serializes access on a single cache.
- `docker-push.yml` adds `workflow_dispatch` for manual re-runs against a release tag; derives the prerelease bit from the tag-name pattern so the `:latest` gate works on both `release.published` and `workflow_dispatch`.
- `npm-publish.yml` derives the npm dist-tag from the tag pattern: prereleases (`-rc*` / `-beta*` / `-alpha*` / `-pre*` / `-dev*`) ship to the `beta` dist-tag; stable tags ship to `latest`. So `npm install @cloak-ward/mcp` (no `@beta`) does not pull a pre-release.
- New `npm-dist-tag.yml` workflow: server-side dist-tag operations using the repo's `NPM_TOKEN` secret. Lets the operator move the dist-tag of an already-published version (e.g. demote rc1 from `latest` to `beta`) without having to wrangle 2FA / token state on their laptop.

### Deferred to v1.0.0
- **Docker image (`ghcr.io/cloakward/cloakd`)** — multi-arch buildx of the cargo cross-compile chain hit a stubborn `error[E0463]: can't find crate for core` on the linux/arm64 row across four iteration attempts. Cleanest fix is to split into native-runner jobs (`ubuntu-24.04` for amd64, `ubuntu-24.04-arm` for arm64) and merge via `docker buildx imagetools create`; that refactor is queued for v1.0.0 work. The `release.published` trigger has been removed from `docker-push.yml`; the workflow stays in-tree on `workflow_dispatch` only. v0.9.0-rc1 ships via the four other install paths (GitHub release tarballs, npm, Homebrew tap, Cloak.dxt). Tracked in [#46](https://github.com/cloakward/cloak/issues/46).

## [0.9.0-rc1] — 2026-05-06

First release candidate for v1.0. Ships macOS arm64/x86_64 + Linux glibc/musl; Windows is deferred to v1.0.1 ([#2](https://github.com/cloakward/cloak/issues/2)). All 11 v1.0 critical-path workstreams (W1, W3–W10, W9b/c/d/e/f) are on `beta`.

### Known caveats

- **Linux pidfd peer-exit watcher** is implemented in source but disabled at the daemon's `serve_conn` call site for this RC; the captured pidfd path tripped a tokio `AsyncFd` registration error on the GitHub Actions runner kernel that we couldn't reproduce locally. Re-enable tracked in [#21](https://github.com/cloakward/cloak/issues/21). macOS kqueue + audit-token path is fully wired and gives full A8 coverage; Linux falls back to socket-FIN-driven session revocation, same surface as v0.1.
- **npm publish two-leg fallback.** OIDC trusted publishing is preferred and attaches `--provenance`. If the npm-side trusted-publisher relationship for `@cloak-ward/mcp` is not yet configured (tracked in [#6](https://github.com/cloakward/cloak/issues/6)), the workflow falls back to a static `NPM_TOKEN` and publishes WITHOUT provenance, with a `::warning::` flagging the gap. Migration to trusted-publishing-only is a v1.0.x follow-up.
- **macos-26-intel (x86_64) release row is best-effort.** macOS x86_64 free-tier runners can take a long time to allocate; the row carries `continue-on-error: true` so a missed allocation drops the row with a workflow warning instead of failing the release. The `macos-guard` job fails the workflow only when BOTH macOS rows are missing. macOS arm64 (`macos-26`) is required and always ships. (Matrix replaces the v0.9.0-rc1-pre macos-13 / macos-14 split.)
- **Biometric (Touch ID / polkit) is enforced by the `cloak` CLI binary, not by `cloakd`.** A same-UID attacker who calls the daemon directly via the IPC socket — bypassing the CLI — gets through with no biometric prompt. v1.0.1 moves the LocalAuthentication / polkit calls into `cloakd` itself so the prompt fires regardless of which peer requested `vault.show`.
- **Rollback counter lives in the vault file only**, not the OS keychain. Read-side rollback (`cloak show` against a restored older snapshot) is not detected; write-side is. v1.0.1 mirrors the counter into the keychain so reads also detect rollback.
- **No passphrase recovery.** v0.9.0-rc1 ships without BIP-39 24-word recovery — if you lose your passphrase, every secret in the vault is permanently unrecoverable. Back up your passphrase out-of-band before adding any secret.

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
