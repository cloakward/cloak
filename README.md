<h1 align="center">Cloak</h1>

<p align="center">
  <strong>Stop pasting API keys into your AI.</strong><br>
  Cloak lets your agents use your keys without ever seeing them.
</p>

<p align="center">
  <a href="docs/RELEASE.md#verify-slsa-l3-provenance"><img src="https://slsa.dev/images/gh-badge-level3.svg" alt="SLSA L3"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="Apache-2.0"></a>
</p>

<p align="center">
  <img src="docs/cloak-demo.gif" alt="Store an API key in Cloak's encrypted vault, then let an agent use it without the model ever seeing the key" width="820">
</p>

Hand an AI agent an API key and you've handed it to the model: its context, its provider's logs, and anyone who can read them. One prompt injection and the key walks out the door.

Cloak keeps your keys in an encrypted vault on your machine. The agent never receives the stored key. It asks Cloak to use the key, and gets back only the result.

- **No `read_secret` tool.** The agent can list, sign, proxy, and mint. It cannot read a stored value.
- **Allowlisted by default.** A key reaches a host only if you approved it.
- **Local only.** No account, no cloud, no telemetry.
- **Signed releases.** macOS-notarized, cosign-signed, SLSA L3-attested.

## Quickstart

macOS (arm64/x64) and Linux (x64 glibc):

```sh
brew install cloakward/cloak/cloak
cloak setup                     # creates the vault, starts the daemon, connects your AI clients
cloak import .env               # pull every key you already have into the encrypted vault
```

That works for any secret: an LLM key, a payments key, a cloud credential, a git token. Add them one at a time instead with `cloak add OPENAI_API_KEY`.

Every secret starts denied. Allow each key to reach a host with one command, applied live with no daemon restart:

```sh
cloak allow OPENAI_API_KEY api.openai.com
cloak allow STRIPE_SECRET_KEY api.stripe.com
cloak policy                    # see what each key can reach
```

Prefer a file? The same rules live in `policy.toml`, one `[[secrets]]` block per secret. Remove a host with `cloak deny`.

Your agent can now use any of them, in plain English. One worked example:

> **You:** test my checkout: create a $50 Stripe PaymentIntent with pm_card_visa and confirm it succeeded.

The agent calls `proxy_authenticated_http_request`. Cloak attaches `STRIPE_SECRET_KEY`, sends the request to Stripe, and returns only the result. This is a real one, captured in test mode:

```text
proxy_authenticated_http_request  →  POST https://api.stripe.com/v1/payment_intents

Status 200
{
  "id": "pi_3ThFkTKCZ65x2cgg0rzmsrj3",
  "amount": 5000,
  "amount_received": 5000,
  "currency": "usd",
  "livemode": false
}
```

A real $50 charge went through. The `STRIPE_SECRET_KEY` that authorized it, which can refund every charge and drain the account, appears nowhere in what the model received.

`cloak setup` connects Claude Desktop, Claude Code, Cursor, Windsurf, Zed, Continue.dev, and Codex that it finds installed. The [quickstart](docs/QUICKSTART.md) covers Linux, Docker, and the Claude Desktop extension.

## How it works

Three pieces:

- **`cloak`**: the CLI you use to add and manage secrets.
- **`cloakd`**: a local daemon that holds the keys and does the privileged work.
- **`cloak-mcp`**: the MCP server your AI client connects to.

Your agent calls a tool on `cloak-mcp`. `cloakd` checks your policy, attaches the secret only for the allowed request, and returns the result. The stored key never reaches the agent or model.

## What it protects (and what it doesn't)

Cloak stops your long-lived key from leaking. It does not make a hijacked agent harmless: a minted token or a proxied response still goes to the agent, and an agent can still misuse the access you allowlisted. It is built for a single-user machine; root and compromised hosts are out of scope. The [threat model](docs/THREAT_MODEL.md) is honest about the rest.

## Documentation

- [Quickstart](docs/QUICKSTART.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Security invariants](docs/SECURITY_INVARIANTS.md)
- [Architecture](docs/ARCHITECTURE.md)
- [MCP tools](docs/spec/mcp-tools.md)
- [FAQ](docs/FAQ.md)

## License

Apache-2.0. See [LICENSE](LICENSE).
