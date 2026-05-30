# Changelog

All notable changes to Cloak. Format follows Keep-a-Changelog; we use SemVer.

## [Unreleased]

## [1.0.3] - 2026-05-30

### Fixed
- Signed the Bun-compiled macOS `cloak-mcp` release binary with the narrow JIT entitlement it needs under hardened runtime, and added release-install checks that verify the entitlement is present only on `cloak-mcp`.
- Fixed Docker release builds by removing the unnecessary `clang` builder package that conflicted with the pinned Debian snapshot and Rust base image package set.
- Made the Homebrew bump workflow merge the stable formula update and verify tap `main` serves the new version before reporting success.

## [1.0.2] - 2026-05-30

### Added
- Added `cloak audit verify`, `cloak daemon restart`, and the `cloak unlock` alias for the existing daemon unlock flow.
- Added explicit `cloak audit adopt-head --yes` recovery for operators upgrading a verified legacy audit log into the new external audit-head anchor model.
- Added explicit `cloak rollback adopt-state --yes` recovery for operators upgrading a reviewed legacy counter-only rollback mirror into the new state-hash mirror model.

### Changed
- Clarified install docs to separate full installs (`cloak`, `cloakd`, `cloak-mcp`) from Claude Desktop `.dxt` shim installs. npm distribution is paused until it can ship audited native `cloak-mcp` binaries per supported platform.
- Hardened release workflows so existing published releases cannot be asset-clobbered, downstream Homebrew/Docker publishes require a successful `release-install-$TAG` marker, manual publish workflows must run from the tag ref, and cosign verification uses exact certificate identities.
- Removed `require_confirmation` from example policies because confirmation is parsed but still fails closed in the daemon.
- Documented that derived tokens are credentials returned to the MCP client, and that proxied upstream responses receive best-effort exact-secret redaction while still requiring trusted allowlisted hosts.
- Tightened Docker, Homebrew, and GitHub Release promotion so downstream publish jobs require release-install evidence bound to the current tag, release ID, checksum file, and exact asset inventory.

### Fixed
- Rejected camelCase credential-shaped field names, credential-bearing URL userinfo/query parameters, and credential-shaped signing headers in both MCP validation and daemon-side checks.
- Redacted JSON-style credential fields in MCP-visible daemon/tool errors.
- Returned unsupported `mint_short_lived_token` kinds before decrypting the parent secret.
- Made stale rollback/audit pending markers unable to downgrade finalized keychain/file anchors.
- Rejected old vault snapshots whose plaintext rollback counter was edited to match the current mirror by binding the mirror to a vault-state digest.
- Made Linux pidfd watcher setup and wait errors fail closed by refusing the handshake or revoking sessions defensively.
- Changed DXT first-run guidance to require terminal setup, daemon start, and `cloak unlock` before restarting Claude Desktop.
- Preserved Homebrew compatibility in DXT/MCP executable trust checks while still rejecting world-writable and broadly group-writable paths.
- Prevented committed vault initialization from reporting success if the one-time recovery mnemonic could not be written.
- Fixed release checksum/provenance gates so `sha256sums.txt` no longer hashes itself but is still cosign-signed and SLSA-verified.
- Fixed Docker release builds to use digest-only per-arch pushes before the final signed multi-arch manifest is created.

## [1.0.1] - 2026-05-28

### Added
- Added the release-install gate for published artifacts: checksum validation, cosign verification, macOS code-signature checks, binary version checks, and shipped-binary smoke tests across macOS and Linux targets.

### Changed
- Promoted the RC3 release-engineering fixes to the stable release line after CI, security, smoke, release signing/notarization, provenance verification, downstream publish jobs, Homebrew tap update, and release-install checks all passed.
- Updated README and launch docs to describe stable macOS/Linux artifacts as production-gated while keeping Windows explicitly outside the shipped release artifacts.

### Fixed
- Added a non-hanging `cloakd --version` / `cloakd -V` path after the RC2 release-install run exposed that the daemon started normally instead of printing a version.

## [1.0.1-rc3] - 2026-05-28

### Fixed
- Added a non-hanging `cloakd --version` / `cloakd -V` path and regression test after the RC2 `release-install` workflow exposed that the daemon started normally instead of printing a version.

## [1.0.1-rc2] - 2026-05-28

### Added
- Added a manual `release-install.yml` workflow that downloads published release tarballs, checks `sha256sums.txt`, verifies cosign signatures, validates macOS code signatures, and runs the daemon/CLI/MCP smoke path from shipped binaries across hosted macOS and Linux runners.
- Extended `scripts/smoke-test.sh` so the same smoke path can run against prebuilt release binaries instead of only source-built binaries.

### Changed
- Updated first-party GitHub Actions, artifact, Docker, and npm dist-tag workflows to Node 24-compatible action majors.
- Documented that signed macOS downloads currently show the personal Apple Developer ID name "Varun Menon" until Cloak has an Apple organization account.
- Clarified that `NPM_TOKEN` remains an intentional npm publish fallback and that Windows is not part of the current release artifacts.

## [1.0.1-rc1] - 2026-05-28

### Security
- Resolved OSV dependency findings in the Rust and MCP dependency graphs, including removal of the legacy `rustls-webpki` 0.101.x path and pinned MCP transitive overrides for `fast-uri`, `hono`, `ip-address`, and `qs`.

### Fixed
- Hardened release and security workflows so prerelease tags are marked as prereleases, Docker `latest` is reserved for stable tags, and OSV scanning runs as a normal pinned job with explicit permissions.
- Updated the smoke test environment guard so test-only passphrase injection requires `CLOAK_UNSAFE_TEST_MODE=1`.
- Refreshed README and launch docs around open-source installation, prerelease trust, Apple signing/notarization expectations, and publisher naming constraints.

## [1.0.0] — 2026-05-08

### Security
- Read-side rollback detection. The vault's monotonic counter is now mirrored into a separate OS-keychain item (`dev.cloak` / `vault.rollback-counter.v1`, 8 bytes big-endian) on every successful write, and `Vault::open_or_create` compares the file counter to the mirror before any record is decrypted. A file counter older than the mirror (backup-restore mishap, malware, bit-flip) is rejected with `Error::VaultRollbackDetected`; a newer file counter is accepted and refreshes the mirror (legitimate cross-device rsync); a missing mirror is seeded from the file (first run after upgrade). With `CLOAK_PEPPER_FILE` set the mirror falls back to a 0600 sibling file (`<vault_dir>/rollback-counter`) — see `docs/THREAT_MODEL.md` for the file-fallback caveat. This was a documented residual risk in v0.9.0-rc1/rc2; deferral note removed.
- Biometric / user-presence is now enforced by `cloakd` directly, not the `cloak` CLI. The daemon fires the Touch ID (macOS) / polkit (Linux) prompt itself before serving `vault.show`, and ignores any client-supplied "user already approved" assertion. A same-UID attacker who connects to the daemon socket directly — bypassing the CLI — no longer skips the prompt; the only documented escape hatch is the explicit `skip_biometric: true` opt-out forwarded by `cloak --no-biometric show NAME` for headless contexts. New `biometric-failed` IPC error code is returned on cancel / failure / unavailable. Threat-model row A9 in `docs/THREAT_MODEL.md`.

### Added
- macOS binaries are now Apple Developer ID signed and submitted to Apple's notary service. Bare Mach-O command-line binaries cannot always be stapled in-place, so Gatekeeper may fetch the ticket online on first launch; packaged installers remain the path for offline-stapled tickets. Cosign keyless signing still happens after notarization so the cosign cert covers the notarized bytes. Steps gracefully skip (with a `::warning::`) when the Apple secrets aren't configured (e.g. forks).
- **BIP-39 24-word recovery seed.** `cloak init` / `cloak setup` now generate a fresh 256-bit entropy, encode it as a 24-word English BIP-39 mnemonic, and store a *second* wrap of the master key under the recovery key (BIP-39 seed via PBKDF2-HMAC-SHA512, first 32 bytes). The mnemonic is shown once with a "WRITE THIS DOWN" warning and is never persisted. New `cloak restore` re-derives the master from the seed and re-wraps it under a freshly chosen passphrase — recovery from a lost passphrase is now possible. New `cloak backup verify` round-trips a candidate seed against the stored recovery wrap. New `cloak backup mnemonic` confirms a vault has a recovery wrap (Touch ID gated + audit-logged). Vaults created before this release do not carry a recovery wrap; `cloak restore` / `cloak backup *` return a clear error on those vaults — in-place migration is queued for v1.1. Schema bumped via migration `0002_recovery_wrap.sql`; the recovery columns are nullable so older vaults continue to open. Recovery is **CLI-only**: no IPC method or MCP tool can access the recovery wrap. The "no passphrase recovery" caveat from rc1 is now resolved.
- release tarballs include cloak-mcp at bin/cloak-mcp on macOS arm64, macOS x64, and Linux gnu amd64; brew/curl installs ship all three binaries with no npm dependency. (Linux musl + Linux arm64 ship cloak + cloakd only because bun --compile can't cross-target those triples — track in a follow-up issue if needed.)
- `Cloak.dxt` extension for Claude Desktop — drag-and-drop install, native setup dialogs. Bundles `cloak-mcp` and runs `cloak setup` via OS-native dialog flow on first activation (no terminal commands required). One `.dxt` per supported MCP-binary platform (macOS arm64/x64 and Linux x64) ships with the GitHub release. Windows and Linux arm64 `.dxt` packages are deferred until their MCP binary builds are supported.

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

### Notes
- The "deferred to v1.0.0" Docker multi-arch line from rc1 is resolved: `docker-push.yml` now splits into native-runner jobs (`ubuntu-24.04` for amd64, `ubuntu-24.04-arm` for arm64) and merges via `docker buildx imagetools create`. `:VERSION`, `:MAJOR_MINOR`, and `:latest` (stable tags only) are pushed to `ghcr.io/cloakward/cloakd`.

## [0.9.0-rc1] — 2026-05-06

First release candidate for v1.0. Ships macOS arm64/x86_64 + Linux glibc/musl; Windows is deferred to v1.0.1 ([#2](https://github.com/cloakward/cloak/issues/2)). All 11 v1.0 critical-path workstreams (W1, W3–W10, W9b/c/d/e/f) are on `beta`.

### Known caveats

- **Linux pidfd peer-exit watcher** is implemented in source but disabled at the daemon's `serve_conn` call site for this RC; the captured pidfd path tripped a tokio `AsyncFd` registration error on the GitHub Actions runner kernel that we couldn't reproduce locally. Re-enable tracked in [#21](https://github.com/cloakward/cloak/issues/21). macOS kqueue + audit-token path is fully wired and gives full A8 coverage; Linux falls back to socket-FIN-driven session revocation, same surface as v0.1.
- **npm publish two-leg fallback.** OIDC trusted publishing is preferred and attaches `--provenance`. If the npm-side trusted-publisher relationship for `@cloak-ward/mcp` is not yet configured (tracked in [#6](https://github.com/cloakward/cloak/issues/6)), the workflow falls back to a static `NPM_TOKEN` and publishes WITHOUT provenance, with a `::warning::` flagging the gap. Migration to trusted-publishing-only is a v1.0.x follow-up.
- **macos-26-intel (x86_64) release row is prerelease-best-effort only.** macOS x86_64 free-tier runners can take a long time to allocate; prerelease previews may continue without the Intel row, but stable tags fail if either macOS architecture is missing. (Matrix replaces the v0.9.0-rc1-pre macos-13 / macos-14 split.)
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
  - TOML policy DSL with default-deny, allowed_hosts, and rate limits. `require_confirmation` is parsed but was not an allow path.
  - `tool.sign_request` (HMAC-SHA256, AWS SigV4), `tool.proxy_http` (reqwest+rustls + allowlist), `tool.mint_token` (AWS STS), `tool.query_audit`.
- Privileged tool handlers wired end-to-end through the daemon:
  - `tool.sign_request` — HMAC-SHA256 over `"{METHOD}\n{URL}\n{sha256_hex(body)}\n"`, returning only `X-Cloak-Signature`.
  - `tool.proxy_http` — strips caller-supplied `Authorization`/`Cookie`/`X-Api-Key`, attaches auth via bearer/basic/header/query, never echoes the auth header back.
  - `tool.mint_token` — `aws-sts` kind calls real STS `GetSessionToken` (post-W1) and returns a base64'd JSON envelope of the temporary credentials with RFC3339 `expires_at`; other kinds return a typed not-supported error (still audited).
  - `tool.query_audit` — filters audit entries by time/tool/secret/result/limit; never returns secret values.
- `crates/cloak-core/src/egress.rs` — single workspace outbound-HTTP module. `reqwest` with rustls TLS, redirects disabled, 30s timeout. `cloak-mcp` remains HTTP-free.
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
