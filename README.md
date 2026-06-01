<h1 align="center">Cloak</h1>

<p align="center">
  <strong>Your AI agent uses your API keys — without ever seeing them.</strong>
</p>

<p align="center">
  <a href="https://github.com/cloakward/cloak/actions/workflows/ci.yml"><img src="https://github.com/cloakward/cloak/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/cloakward/cloak/attestations"><img src="https://slsa.dev/images/gh-badge-level3.svg" alt="SLSA L3"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="Apache-2.0"></a>
</p>

Pasting an API key into a chat hands it to the model, its logs, and its provider. Cloak keeps your keys in an encrypted vault on your machine and lets your agent *use* them through narrow actions — sign a request, call an allowlisted API, mint a short-lived token. The agent gets the result; the raw stored key stays out of the chat and model context.

## Install

macOS (arm64/x64) and Linux (x64 glibc):

```sh
brew install cloakward/cloak/cloak
cloak setup
```

`cloak setup` creates the vault, starts the daemon, and registers your AI clients — Claude Desktop, Claude Code, Cursor, Windsurf, Zed, Continue.dev, Codex.

Then add a secret and unlock:

```sh
cloak add OPENAI_API_KEY
cloak unlock
```

To let an agent call an API, you allowlist the host first. The [quickstart](docs/QUICKSTART.md) covers that, plus other platforms, Docker, and the Claude Desktop `.dxt`.

## What it looks like

> **You:** What PRs am I being asked to review?
>
> **Claude:** *Calls `proxy_authenticated_http_request` on `api.github.com` — Cloak attaches your `GITHUB_TOKEN` server-side and returns the result.*
>
> You have 3 open review requests:
> - **acmecorp/api#412** — feat: cache layer for `/v1/users`
> - **acmecorp/worker#198** — fix: race in graceful shutdown
> - **acmecorp/sdk-js#67** — docs: clarify rate-limit headers

The call is policy-checked, run by the local daemon, and written to a hash-chained audit log. Your `GITHUB_TOKEN` never reaches the model.

## Why Cloak

- **Local first.** Vault and daemon run on your machine. No hosted service, no signup, no telemetry.
- **No `read_secret` tool.** Agents get action-shaped tools, never the raw value.
- **Allowlisted by default.** API proxying is denied until you permit a specific secret and host.
- **Presence-gated reveal.** `cloak show` is a deliberate Touch ID / polkit prompt by default.
- **Verifiable releases.** Signed, macOS-notarized, and SLSA L3-attested — verification steps in [RELEASE.md](docs/RELEASE.md).

## What it protects — and what it doesn't

Cloak stops your agent from *exfiltrating or storing* your long-lived keys. It does not make the agent trustworthy with the access those keys grant:

- `mint_short_lived_token` returns a scoped token to the agent on purpose.
- `proxy_authenticated_http_request` returns the upstream response to the agent.
- Root, a compromised build host, or a user who pipes secrets elsewhere are out of scope.

Full detail: [threat model](docs/THREAT_MODEL.md) and [security invariants](docs/SECURITY_INVARIANTS.md).

## Documentation

- [Quickstart](docs/QUICKSTART.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Security invariants](docs/SECURITY_INVARIANTS.md)
- [MCP tool spec](docs/spec/mcp-tools.md)
- [FAQ](docs/FAQ.md)
- [Privacy](docs/PRIVACY.md)

## License

Apache-2.0. See [LICENSE](LICENSE).
