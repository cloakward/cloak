# Cloak security invariants

These are the load-bearing properties Cloak enforces in code, in tests, and in
CI. Each invariant lists the implementation area where it is enforced, the
test that asserts it, and the CI check that gates regressions.

`README.md` links here and carries only a short summary; this file is the
source of truth.

## I1 — No MCP tool returns raw stored secret values

The MCP-callable surface contains no `get_secret` / `reveal_secret` /
`read_secret` method. Every tool returns either metadata (names, kinds, tags),
the result of a privileged daemon-side action (computed headers, HTTP response,
minted derivative), or an audit query — never a raw stored secret value. The
minted derivative is still a credential returned to the MCP client by design,
and proxied HTTP responses are returned without arbitrary body redaction.

- **Enforced:** `packages/cloak-mcp/src/tools/index.ts:9-16` (the six-tool
  registry; nothing else is exposed) and the per-tool handlers in the same
  directory, which only forward to `vault.list`, `vault.get_metadata`,
  `tool.sign_request`, `tool.proxy_http`, `tool.mint_token`, `tool.query_audit`.
  The daemon's CLI-only dispatch gate in `crates/cloak-core/src/daemon.rs`
  keeps `vault.show` reachable only by the `cloak` CLI peer, and the
  daemon-side `vault.show` handler performs user-presence verification before
  plaintext leaves the vault.
- **Tested:** `packages/cloak-mcp/tests/tools.test.ts:140-161`
  ("no tool returns plaintext-looking secret material") and the description
  contract test at `packages/cloak-mcp/tests/tools.test.ts:163-200`.
  `crates/cloak-core/tests/handlers_e2e.rs:319` (sign_request leak guard) and
  `crates/cloak-core/tests/handlers_e2e.rs:756` (no_leak_invariant_for_aws_handlers).
- **CI gate:** `cloak-mcp install + lint + test + build` step in
  `.github/workflows/ci.yml`.

## I2 — The daemon owns all outbound HTTP

`cloak-mcp` imports zero HTTP clients. Network egress is daemon-owned and
limited to explicit tool calls: `proxy_authenticated_http_request` goes through
`crates/cloak-core/src/egress.rs` (reqwest + rustls + system root store,
redirects disabled, 30s timeout), while `mint_short_lived_token` uses the AWS
Smithy STS client in `crates/cloak-core/src/handlers.rs` with a daemon-side
30-second timeout. `egress.rs` additionally refuses any non-global destination
address (loopback/private/link-local/metadata/ULA) for both IP-literal hosts
and hostnames — the hostname filter runs in the DNS resolver reqwest connects
through, so DNS-rebinding cannot slip a private address past the host allowlist
(tested in `crates/cloak-core/src/egress.rs::tests`). Host allowlists apply to
proxy requests; STS minting is
gated by tool/secret policy instead.

- **Enforced:** `packages/cloak-mcp/scripts/check-no-http.mjs:14-24` rejects
  any import of `http`, `https`, `node:http`, `node:https`, `axios`, `undici`,
  `node-fetch`, or `got`, and any bare `fetch(` call.
- **Tested:** `packages/cloak-mcp/tests/no-http.test.ts` invokes the script
  against the real `src/` tree on every test run.
- **CI gate:** `bun run lint:no-http` in the MCP test step.

## I3 — Peer auth runs before any session token issuance

A connection from an unknown binary (basename not on the allowlist), an
unknown UID, with no resolvable on-disk path, with a mismatched installed
binary hash, or on macOS with a mismatched running-process CodeDirectory hash
is closed before the daemon writes anything to it. No session token is minted.
On Linux the hash prefers the kernel-pinned `/proc/<pid>/exe` bytes and falls
back to the resolved executable path only when procfs denies opening the
sibling process image.

- **Enforced:** `crates/cloak-core/src/daemon.rs:235-252` (peer-auth happens
  immediately after `accept`, before any `read_request_json`) calling
  `crates/cloak-core/src/peer_auth.rs:100-109`.
- **Tested:** `crates/cloak-core/src/peer_auth.rs:342-389` (happy path,
  uid mismatch, basename not in allowlist, missing binary path,
  require_same_uid toggle).
- **CI gate:** `cargo test --workspace`.

## I4 — Policy is checked before vault read

Every privileged tool handler runs the policy gate (and rate-limit bucket)
before touching the vault. A denied call writes an audit entry with
`result: "denied"` and never decrypts the secret.

- **Enforced:** `crates/cloak-core/src/handlers.rs:109-185` (`enforce_policy`
  is called first; the vault `show()` happens later, e.g.
  `crates/cloak-core/src/handlers.rs:243-249` in `sign_request`).
- **Tested:** `crates/cloak-core/tests/handlers_e2e.rs::proxy_http_disallowed_host_denied`
  asserts a denied call writes the audit `Denied` entry and never reads the
  secret.
- **CI gate:** `cargo test --workspace`.

## I5 — libsodium only, no rolling our own

AEAD is XChaCha20-Poly1305-IETF; KDF is Argon2id keyed mode; per-record
subkeys come from `crypto_kdf_derive_from_key` (BLAKE2b under the hood);
nonces come from `randombytes_buf`. `sha2` is used **only** for the audit
hash chain and code-signature digests, never as a primitive in the
secret-protection path.

- **Enforced:** `crates/cloak-core/src/crypto.rs:176-187` (AEAD seal),
  `crates/cloak-core/src/crypto.rs:216-227` (AEAD open),
  `crates/cloak-core/src/crypto.rs:366-381` (Argon2id KDF, ALG_ARGON2ID13),
  `crates/cloak-core/src/crypto.rs:533-542` (`crypto_kdf_derive_from_key`),
  `crates/cloak-core/src/crypto.rs:239-243` (`randombytes_buf` for nonces).
  Master-key wrap with AAD `cloak.master.v1` at
  `crates/cloak-core/src/vault.rs:40,210,246`.
  `CONTRIBUTING.md:32-35` lists the dependency-graph invariant
  (no `ring`/`aws-lc-rs`/`aes-gcm`/`chacha20poly1305` in the secret path).
- **Tested:** `crates/cloak-core/src/crypto.rs::tests` (kdf_determinism,
  kdf_different_passphrases_diverge, kdf_different_peppers_diverge),
  `crates/cloak-core/src/vault.rs::tests::aad_swap_attack_fails`,
  `crates/cloak-core/src/vault.rs::tests::tampered_ciphertext_typed_error_not_panic`.
  `cargo deny` enforces the dependency-graph at audit time
  (`deny.toml`).
- **CI gate:** `cargo test --workspace`; `cargo deny` (W9-series).

## I6 — `Secret<T>` zeroize-on-drop everywhere

Every secret-typed value is wrapped in `crypto::Secret<T>`, which redacts
`Debug` to `"***"` and zeroizes its inner buffer on drop. The only accessor
is `expose_secret()`, so reads are grep-able.

- **Enforced:** `crates/cloak-core/src/crypto.rs:34-79` defines `Secret<T>`,
  its `Debug`, and its `Drop` impl. `expose_secret()` is the only read
  accessor.
- **Tested:** `crates/cloak-core/src/vault.rs::tests` exercise `Secret`
  round-trips through every public vault method (init, add, set, show, lock,
  unlock); the `Secret<T>` wrapper would prevent compilation if a bare
  `String` leaked.
- **CI gate:** `cargo clippy --workspace --all-targets -- -D warnings`
  (which catches `Debug` impls that would print interior state).

## Supplementary invariants

### S1 — Audit log is hash-chained and tamper-evident
`crates/cloak-core/src/audit.rs:160-186` builds each entry's `prev_hash` over
the canonical-JSON serialization of the previous entry. `verify()` at
`crates/cloak-core/src/audit.rs:188-220` rejects mutated/deleted/reordered
lines. Tested at `crates/cloak-core/src/audit.rs::tests::append_100_and_verify`
and `concurrent_appends_are_atomic_and_complete`. The current tail is also
anchored outside the log; non-empty logs with no anchor fail closed unless an
operator explicitly adopts the verified current head with
`cloak audit adopt-head --yes`.

### S2 — Session tokens use constant-time compare
`crates/cloak-core/src/session.rs:124` uses `subtle::ConstantTimeEq::ct_eq`
on the token bytes. (`THREAT_MODEL.md` listed this as a v0.1 residual risk;
the v1.0 fix landed pre-tag.)

### S3 — Vault rollback is rejected
A monotonic counter lives in the vault's `meta` table and is mirrored
into a separate OS-keychain item (`dev.cloak` / `vault.rollback-counter.v1`,
or a 0600 `rollback-counter` file alongside `CLOAK_PEPPER_FILE`) together
with a SHA-256 commitment to the logical vault state. `Vault::open_or_create`
compares the file state to the external mirror and rejects with
`Error::VaultRollbackDetected` whenever an existing mirror differs, so
read-side rollback is caught before any record is decrypted. Binding the
mirror to the state digest prevents an attacker from restoring an old
SQLite snapshot and editing only the plaintext counter to match the current
mirror.
Pre-1.0.2 counter-only mirrors are not silently adopted; the operator must
explicitly run `cloak rollback adopt-state --yes` after reviewing the current
vault file.
The write-side gate (`crates/cloak-core/src/store.rs::bump_counter`) is
covered by `crates/cloak-core/src/vault.rs::tests::rollback_counter_rejected_via_store`;
the read-side gate end-to-end is covered by
`crates/cloak-core/tests/rollback_mirror.rs`.

### S4 — Per-record AAD prevents cross-record swap
The AAD bound to each record's ciphertext is
`name_len_be(u32) || name_utf8 || created_unix_be(i64) || version_be(u64)`
(`crates/cloak-core/src/vault.rs:414-426`). Tested by
`crates/cloak-core/src/vault.rs::tests::aad_swap_attack_fails`.
