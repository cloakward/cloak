<!--
Cite the PLAN.md workstream this PR closes (e.g. "W1") in the title.
-->

## What changed

<!-- One paragraph. -->

## Security invariants touched

Tick every load-bearing invariant this change reads, modifies, or weakens. If
none, say so explicitly.

- [ ] No MCP tool returns plaintext secret material
- [ ] Daemon owns all outbound HTTP (cloak-mcp HTTP-free)
- [ ] Peer auth runs before any session token issuance
- [ ] Policy is checked before vault read
- [ ] libsodium is the only crypto primitive in the secret-protection path
- [ ] `Secret<T>` zeroize-on-drop discipline preserved

If any box is ticked, link to the test that backs the change.

## Test plan

- [ ] `cargo test --workspace` green
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] `bun run lint:no-http && bun test` (in `packages/cloak-mcp`) green
- [ ] `./scripts/smoke-test.sh` green (if touching the daemon, IPC, or handlers)

## PLAN.md exit gate

<!-- Quote the bullet from PLAN.md §3 W<N> "Exit gate" that this PR satisfies. -->
