<h1 align="center">Cloak</h1>

<p align="center">
  <strong>Your AI agent uses your API keys without ever seeing them.</strong>
</p>

<p align="center">
  <a href="https://github.com/cloakward/cloak/actions/workflows/ci.yml"><img src="https://github.com/cloakward/cloak/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/cloakward/cloak/attestations"><img src="https://slsa.dev/images/gh-badge-level3.svg" alt="SLSA L3"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="Apache-2.0"></a>
</p>

Pasting your API key into an AI chat is the new `rm -rf /`. Once the model has it, the value has been logged, cached, and possibly trained on. Cloak is a local secrets daemon that lets your agent do its job (sign requests, call APIs, mint short-lived tokens) while keeping raw stored secret values out of the model's context.

## Status

Cloak's macOS and Linux release artifacts are production-gated. Stable tags must pass CI, security scans, smoke tests, Apple signing/notarization, and cosign/SLSA verification before the draft GitHub Release is created. Maintainers run release-asset install tests against that draft, then publish through the marker-gated `publish-release.yml` workflow; downstream Homebrew and Docker publishing also require the matching install-test marker bound to the current release assets.

Current release notes:

- Stable production tags are hard-gated on macOS Developer ID signing and Apple notarization secrets. If those secrets are missing, the macOS release rows fail instead of silently publishing unsigned artifacts.
- macOS trust prompts for signed downloads may show the individual Apple Developer ID name "Varun Menon". That is expected for the current personal developer account; a product/company signer name requires an Apple organization account.
- Linux daemon peer-auth requires Linux 6.5+ for `SO_PEERPIDFD`; older kernels fail closed before issuing a session token.
- Prerelease/fork preview tags may still be unsigned. Treat them as test builds and expect Gatekeeper friction on macOS.
- Release tags built by the current workflow sign and SLSA-attest the tarballs, `sha256sums.txt`, and macOS Claude Desktop `.dxt` packages. Older preview `.dxt` assets may not have `.sig` / `.cert` files or SLSA subjects; do not treat those as verified.
- npm distribution is paused until it can ship audited native `cloak-mcp` binaries per supported platform. Use Homebrew, release tarballs, or signed macOS `.dxt` assets for Claude Desktop installs.
- Windows support and production installer polish are still pending.

## Install

### Full install: CLI + daemon + MCP shim

On macOS arm64/x64 and Linux x64 glibc, the simplest stable install path is
Homebrew:

```sh
brew install cloakward/cloak/cloak
cloak setup
```

For Linux x64 musl or Linux arm64, use the verified release tarball for your
target from GitHub Releases. Linux x64 musl and Linux arm64 currently ship the
CLI and daemon only; native `cloak-mcp` packages are built for macOS arm64/x64
and Linux x64 glibc.

Build from source when you need the most direct local audit path:

```sh
git clone https://github.com/cloakward/cloak
cd cloak
./scripts/prepare-libsodium-dist.sh
SODIUM_DIST_DIR="$PWD/.cargo/libsodium-dist" cargo build --release --workspace
cd packages/cloak-mcp && bun install --frozen-lockfile && bun run build
cd ../..
mkdir -p "$HOME/.local/bin"
install -m 755 target/release/cloak "$HOME/.local/bin/cloak"
install -m 755 target/release/cloakd "$HOME/.local/bin/cloakd"
install -m 755 packages/cloak-mcp/dist/cloak-mcp "$HOME/.local/bin/cloak-mcp"
```

For source builds, keep `cloak`, `cloakd`, and `cloak-mcp` installed in the
same directory. The daemon pins trusted client binaries by hash at startup and
trusts the `cloak-mcp` sibling next to `cloakd`; pointing Claude Desktop at a
different build output can make MCP handshakes fail.

The setup wizard takes about 60 seconds. It auto-detects Claude Desktop, Claude Code, Cursor, Windsurf, Continue.dev, Zed, and Codex, and wires them all up.

```sh
cloak add OPENAI_API_KEY               # input is hidden as you type
cloak list                             # see what's in the vault
cloak run --only OPENAI_API_KEY -- python my_script.py
cloak run --all -- printenv            # deliberate all-secret injection
```

### MCP shim only

Claude Desktop users on macOS can drag-and-drop a verified [`Cloak-*.dxt`](https://github.com/cloakward/cloak/releases) after the full CLI + daemon install is present. The `.dxt` installs the `cloak-mcp` shim only; it does not install the vault CLI or `cloakd` daemon. Full options are in [`docs/QUICKSTART.md`](docs/QUICKSTART.md); release verification is in [`docs/RELEASE.md`](docs/RELEASE.md).

## Why Cloak

- **Local first.** Your vault and daemon run on your machine. No cloud, no signups, no telemetry.
- **No raw stored-secret reveal tool.** Six action-shaped MCP tools. There is no `read_secret` in the MCP surface.
- **Derived outputs are explicit.** `mint_short_lived_token` can return a temporary credential to the model by design. Treat that as scoped credential exposure, controlled by policy, TTL, and audit.
- **User-presence gated reveal.** `cloak show` prompts by default, and daemon-served plaintext reveal always prompts inside `cloakd`, so a same-UID process cannot skip the CLI and lie its way to plaintext.
- **24-word recovery seed.** Lose your passphrase, restore from a paper backup. Same idea as a hardware wallet.
- **Verifiable releases, when gated.** Production macOS tags must be Developer ID signed and Apple-notarized; tarballs and `.dxt` packages from the current release workflow are cosign-signed and SLSA-attested.
- **Open source, Apache-2.0.** Read the code, build from source, change what you want.

## What it looks like

> **You:** What PRs am I being asked to review?
>
> **Claude:** Let me check.
>
> _Calls `proxy_authenticated_http_request` against `api.github.com/search/issues?q=is:pr+review-requested:@me+state:open`. Cloak attaches `GITHUB_TOKEN` server-side. The model does not receive the stored token value._
>
> **Claude:** You have 3 open review requests:
> - **acmecorp/api#412** — feat: cache layer for `/v1/users` (priya, 2d)
> - **acmecorp/worker#198** — fix: race in graceful shutdown (alex, 5h)
> - **acmecorp/sdk-js#67** — docs: clarify rate-limit headers (jay, 1d)

The stored token never entered the model's context. Cloak attached it to the request, then returned the upstream status, headers, and body. Cloak applies best-effort exact-secret redaction to proxied responses, but it cannot prove a remote API will never echo transformed credentials or unrelated sensitive data, so only allow hosts you trust. The action is recorded with the secret name, target host, and a hash-chain link in the platform audit log (`~/Library/Application Support/cloak/audit.jsonl` on macOS, `~/.local/share/cloak/audit.jsonl` on Linux); the stored value itself is not.

## Security invariants

Cloak's load-bearing security properties are tracked in [`docs/SECURITY_INVARIANTS.md`](docs/SECURITY_INVARIANTS.md). The short version:

- MCP tools do not expose a raw stored-secret reveal path.
- The daemon owns outbound HTTP and attaches secrets server-side.
- Peer authentication runs before session-token issuance.
- Policy checks happen before vault reads.
- Vault rollback and audit-log truncation are anchored outside the vault/log.

## Documentation

- **Quickstart** [`docs/QUICKSTART.md`](docs/QUICKSTART.md)
- **Architecture** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- **Threat model** [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- **MCP tool spec** [`docs/spec/mcp-tools.md`](docs/spec/mcp-tools.md)
- **FAQ** [`docs/FAQ.md`](docs/FAQ.md)
- **Privacy disclosure** [`docs/PRIVACY.md`](docs/PRIVACY.md)

## License

Apache-2.0. See [`LICENSE`](LICENSE).
