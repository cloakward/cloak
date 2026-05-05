# Contributing

Cloak is a token saver / secrets vault. The bar is correctness on the load-bearing
security invariants and small, traceable changes. Lean on existing well-tested
crates rather than rolling our own.

## Dev setup

```sh
# macOS
brew install libsodium bun rustup-init && rustup-init -y
cargo build --workspace
(cd packages/cloak-mcp && bun install)
./scripts/smoke-test.sh   # end-to-end sanity
```

## Workflow

1. Read [`PLAN.md`](PLAN.md). Pick the lowest-numbered open workstream that is
   unblocked. Cite it in your branch name (`feat/w3-ci-matrix`) and PR title.
2. One workstream per PR. Smaller is better. If a workstream is two days of
   work, it's two PRs.
3. Tests first. The PR template asks which security invariant your change
   touches; you must answer before merge.

## Hard rules (non-negotiable)

- **No MCP tool returns plaintext secret material.** New tools require a
  Discussion + varun approval (see PLAN.md §6).
- **Daemon owns all outbound HTTP.** `packages/cloak-mcp` imports zero HTTP
  clients. The grep gate in `scripts/check-no-http.mjs` enforces this.
- **libsodium is the only crypto primitive in the secret-protection path.**
  No `ring` / `aws-lc-rs` / `aes-gcm` / `chacha20poly1305` (RustCrypto).
  rustls/ring as a TLS provider for outbound HTTP is fine; AWS SDK use of
  HMAC-SHA256 internally is fine.
- **No `unsafe` Rust outside `peer_auth/` and `codesign/`** without a
  Discussion + varun approval.
- **No secret material in logs, errors, panics, or audit notes.** Test
  fixtures use the literal `REDACTED`.
- **`Secret<T>` for every secret-typed value.** Accessor is
  `expose_secret()` so reads are greppable.

## PR checklist

The PR template is the canonical checklist. The minimum:

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
(cd packages/cloak-mcp && bun run lint:no-http && bun test)
./scripts/smoke-test.sh   # if your change touches daemon/IPC/handlers
```

## Commit style

`<workstream>: <imperative summary>` — e.g. `W1: replace SigV4 stub with
aws-sigv4`. Body explains *why* and any non-obvious tradeoff.

## Escalation

When in doubt, stop and ask. The triggers are listed in PLAN.md §6. Cost of
asking: one hour. Cost of a wrong silent decision: the project's
trustworthiness.

License: Apache-2.0. By contributing, you license your work under the same.
