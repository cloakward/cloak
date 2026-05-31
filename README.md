<h1 align="center">Cloak</h1>

<p align="center">
  <strong>Let AI agents use your APIs without handing them your stored secret values.</strong>
</p>

<p align="center">
  <a href="https://github.com/cloakward/cloak/actions/workflows/ci.yml"><img src="https://github.com/cloakward/cloak/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/cloakward/cloak/attestations"><img src="https://slsa.dev/images/gh-badge-level3.svg" alt="SLSA L3"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="Apache-2.0"></a>
</p>

Cloak is a local secrets daemon for AI agents. Instead of pasting API keys into a prompt, you store them in an encrypted local vault. Your agent asks Cloak to perform narrow actions - sign a request, call an allowlisted API host, or mint a short-lived token - and Cloak attaches the credential server-side.

Agents get useful results. Raw stored secrets stay out of model-visible MCP tool output.

## Install

On macOS arm64/x64 and Linux x64 glibc:

```sh
brew install cloakward/cloak/cloak
cloak setup
cloak add OPENAI_API_KEY
cloak unlock
```

`cloak setup` creates the vault, installs/starts the daemon, and helps register supported MCP clients such as Claude Desktop, Claude Code, Cursor, Windsurf, Continue.dev, Zed, and Codex.

For Linux x64 musl, Linux arm64, Docker/GHCR, verified tarballs, source builds, and Claude Desktop `.dxt` setup, see the [quickstart](docs/QUICKSTART.md). Windows installers are not part of the current release yet.

## What It Looks Like

> **You:** What PRs am I being asked to review?
>
> **Claude:** Let me check.
>
> _Calls `proxy_authenticated_http_request` against `api.github.com/search/issues?q=is:pr+review-requested:@me+state:open`. Cloak attaches `GITHUB_TOKEN` server-side. The model does not receive the stored token value._
>
> **Claude:** You have 3 open review requests:
> - **acmecorp/api#412** - feat: cache layer for `/v1/users` (priya, 2d)
> - **acmecorp/worker#198** - fix: race in graceful shutdown (alex, 5h)
> - **acmecorp/sdk-js#67** - docs: clarify rate-limit headers (jay, 1d)

The action is policy-checked, executed by the local daemon, and written to a hash-chained audit log. The stored token never enters the model context.

## Why Cloak

- **Local first.** The vault and daemon run on your machine. No hosted vault, no signup, no telemetry.
- **No raw-secret reveal tool for MCP.** Agents get action-shaped tools, not `read_secret`.
- **Policy before use.** API proxying is allowlisted by secret and host before Cloak reads the vault.
- **User-present reveal by default.** `cloak show` is a deliberate CLI action with a local prompt unless the user explicitly chooses a headless bypass.
- **Recovery seed.** Vault creation prints a 24-word recovery seed once. Write it down.
- **Verifiable releases.** Current stable releases are built by CI, macOS Developer ID signed and notarized, cosign-signed, and SLSA L3 attested.
- **Open source.** Apache-2.0.

## Be Precise About The Security Model

Cloak is designed to keep raw stored secret values out of model-visible MCP tool output. That is narrower than "the model never sees any credential material":

- `mint_short_lived_token` intentionally returns a scoped temporary credential to the MCP client.
- `proxy_authenticated_http_request` returns the upstream response body. Cloak strips the auth header it attached and applies best-effort exact-secret redaction, but it cannot prove a remote API will never echo transformed credentials or unrelated sensitive data.
- A root/kernel-level local attacker, a compromised build machine, or a user who deliberately pipes secrets into another tool is outside Cloak's protection boundary.

Read the full [threat model](docs/THREAT_MODEL.md) and [security invariants](docs/SECURITY_INVARIANTS.md) before relying on Cloak for sensitive workflows.

## Verification

Stable release artifacts are published with checksums, cosign signatures/certificates, and SLSA provenance. macOS binaries are Developer ID signed and Apple notarized. Current stable Docker channels are signed through the release workflow.

Verification commands and release-gate details live in [docs/RELEASE.md](docs/RELEASE.md).

## Documentation

- [Quickstart](docs/QUICKSTART.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Security invariants](docs/SECURITY_INVARIANTS.md)
- [MCP tool spec](docs/spec/mcp-tools.md)
- [FAQ](docs/FAQ.md)
- [Privacy disclosure](docs/PRIVACY.md)

## License

Apache-2.0. See [LICENSE](LICENSE).
