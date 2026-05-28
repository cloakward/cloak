<h1 align="center">Cloak</h1>

<p align="center">
  <strong>Your AI agent uses your API keys without ever seeing them.</strong>
</p>

<p align="center">
  <a href="https://github.com/cloakward/cloak/actions/workflows/ci.yml"><img src="https://github.com/cloakward/cloak/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/cloakward/cloak/attestations"><img src="https://slsa.dev/images/gh-badge-level3.svg" alt="SLSA L3"></a>
  <a href="https://www.npmjs.com/package/@cloak-ward/mcp"><img src="https://img.shields.io/npm/v/@cloak-ward/mcp.svg?label=%40cloak-ward%2Fmcp" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="Apache-2.0"></a>
</p>

<p align="center">
  <img src="docs/cloak-demo.gif" width="720" alt="Cloak demo">
</p>

Pasting your API key into an AI chat is the new `rm -rf /`. Once the model has it, the value has been logged, cached, and possibly trained on. Cloak is a local secrets daemon that lets your agent do its job (sign requests, call APIs, mint short-lived tokens) without the keys ever entering the model's context.

## Status

Cloak is beta software. Source builds are the recommended path until the first production release tag passes the current release gate end to end.

Current release notes:

- Stable production tags are hard-gated on macOS Developer ID signing and Apple notarization secrets. If those secrets are missing, the macOS release rows fail instead of silently publishing unsigned artifacts.
- Prerelease/fork preview tags may still be unsigned. Treat them as test builds and expect Gatekeeper friction on macOS.
- Release tags built by the current workflow sign and SLSA-attest the tarballs, `sha256sums.txt`, and Claude Desktop `.dxt` packages. Older preview `.dxt` assets may not have `.sig` / `.cert` files or SLSA subjects; do not treat those as verified.
- Windows support and production installer polish are still pending.

## Install

During beta, build from source when you need the most direct trust path:

```sh
git clone https://github.com/cloakward/cloak
cd cloak
cargo build --release --workspace
cd packages/cloak-mcp && bun install --frozen-lockfile && bun run build
```

Packaged channels are previews unless the release artifacts include matching signatures/provenance:

```sh
brew install cloakward/cloak/cloak
cloak setup
```

The setup wizard takes about 60 seconds. It auto-detects Claude Desktop, Claude Code, Cursor, Windsurf, Continue.dev, Zed, and Codex, and wires them all up.

```sh
cloak add OPENAI_API_KEY               # input is hidden as you type
cloak list                             # see what's in the vault
cloak run -- python my_script.py       # inject as env vars, biometric gated
```

Other ways to install: `npm install -g @cloak-ward/mcp`, drag-and-drop a verified [`Cloak-*.dxt`](https://github.com/cloakward/cloak/releases) for Claude Desktop, or build from source. Full options in [`docs/QUICKSTART.md`](docs/QUICKSTART.md); release verification is in [`docs/RELEASE.md`](docs/RELEASE.md).

## Why Cloak

- **Local first.** Your vault and daemon run on your machine. No cloud, no signups, no telemetry.
- **The model never sees plaintext.** Six action-shaped MCP tools. There is no `read_secret` and there will never be one.
- **User-presence gated reveal.** `cloak show` prompts by default, and daemon-served plaintext reveal always prompts inside `cloakd`, so a same-UID process cannot skip the CLI and lie its way to plaintext.
- **24-word recovery seed.** Lose your passphrase, restore from a paper backup. Same idea as a hardware wallet.
- **Verifiable releases, when gated.** Production macOS tags must be Developer ID signed and Apple-notarized; tarballs and `.dxt` packages from the current release workflow are cosign-signed and SLSA-attested.
- **Open source, Apache-2.0.** Read the code, build from source, change what you want.

## What it looks like

> **You:** What PRs am I being asked to review?
>
> **Claude:** Let me check.
>
> _Calls `proxy_authenticated_http_request` against `api.github.com/search/issues?q=is:pr+review-requested:@me+state:open`. Cloak attaches `GITHUB_TOKEN` server-side. The model never sees the value._
>
> **Claude:** You have 3 open review requests:
> - **acmecorp/api#412** — feat: cache layer for `/v1/users` (priya, 2d)
> - **acmecorp/worker#198** — fix: race in graceful shutdown (alex, 5h)
> - **acmecorp/sdk-js#67** — docs: clarify rate-limit headers (jay, 1d)

The token never entered the model's context. Cloak attached it to the request, returned only the response body. The action is recorded with the secret name, target host, and a hash-chain link in `~/.local/share/cloak/audit.jsonl`; the value itself is not.

## Documentation

- **Quickstart** [`docs/QUICKSTART.md`](docs/QUICKSTART.md)
- **Architecture** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- **Threat model** [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- **MCP tool spec** [`docs/spec/mcp-tools.md`](docs/spec/mcp-tools.md)
- **FAQ** [`docs/FAQ.md`](docs/FAQ.md)

## License

Apache-2.0. See [`LICENSE`](LICENSE).
