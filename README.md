<h1 align="center">Cloak</h1>

<p align="center">
  <strong>A local vault that lets AI agents use your API keys without seeing the stored key.</strong>
</p>

<p align="center">
  <a href="docs/RELEASE.md#verify-slsa-l3-provenance"><img src="https://slsa.dev/images/gh-badge-level3.svg" alt="SLSA L3"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="Apache-2.0"></a>
</p>

<p align="center">
  <img src="docs/cloak-demo.gif" alt="Store an API key in Cloak's encrypted vault, then let an agent use it without the model ever seeing the key" width="820">
</p>

Give an AI agent an API key and you've handed it to the model, its logs, and whoever runs the model. If the agent gets prompt-injected, the key walks out with it.

Cloak keeps your keys in an encrypted vault on your machine. The agent never receives the stored key. It asks Cloak to do the thing the key is for, and gets back only the result.

- **No `read_secret` tool.** The model can list metadata, sign, proxy, and mint. It cannot read a stored value.
- **Local only.** No account, no cloud, no telemetry.
- **Allowlisted by default.** An agent reaches a host only if you approved it for that key.
- **Signed releases.** Stable artifacts are macOS-notarized, cosign-signed, and SLSA L3-attested.

## Example

> **You:** test my checkout — create a $20 charge and confirm it succeeds.
>
> **Claude:** *(calls `proxy_authenticated_http_request` on `api.stripe.com`; Cloak attaches your `STRIPE_SECRET_KEY` and runs the request)*
>
> ✓ `pi_3Q2k…` succeeded — $20.00, `card_visa`. Your checkout works.

Claude tested it against the live API. Your `STRIPE_SECRET_KEY` — which can refund every charge and drain the account — never reached the model.

## Install

macOS (arm64/x64) and Linux (x64 glibc):

```sh
brew install cloakward/cloak/cloak
cloak setup
```

`cloak setup` walks you through creating the vault, starting the daemon, and registering the AI clients it finds installed. Claude Desktop, Claude Code, Cursor, Windsurf, Zed, Continue.dev, and Codex are all supported.

Add your first key:

```sh
cloak add OPENAI_API_KEY
cloak unlock
```

Before an agent can call an API, you allowlist the host for that key. The [quickstart](docs/QUICKSTART.md) covers that, plus Linux, Docker, and the Claude Desktop extension.

## How it works

Cloak is three pieces:

- **`cloak`**: the CLI you use to add and manage secrets.
- **`cloakd`**: a local daemon that holds the keys and does the privileged work.
- **`cloak-mcp`**: the MCP server your AI client connects to.

Your agent calls a tool on `cloak-mcp`. `cloakd` checks your policy, attaches the secret only for the allowed upstream request, and returns the result. The stored key never reaches the agent or model.

## What it protects, and what it doesn't

Cloak stops your long-lived key from leaking. It does not make a hijacked agent safe to ignore:

- `mint_short_lived_token` hands the agent a scoped, expiring token on purpose.
- `proxy_authenticated_http_request` returns the API's response to the agent.
- An agent can still misuse the access you granted on an allowlisted host.

Cloak is built for a single-user machine. Root, a compromised build host, or a user who pipes their own secrets out are out of scope. The full [threat model](docs/THREAT_MODEL.md) spells out the rest.

## Documentation

- [Quickstart](docs/QUICKSTART.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Security invariants](docs/SECURITY_INVARIANTS.md)
- [Architecture](docs/ARCHITECTURE.md)
- [MCP tools](docs/spec/mcp-tools.md)
- [FAQ](docs/FAQ.md)

## License

Apache-2.0. See [LICENSE](LICENSE).
