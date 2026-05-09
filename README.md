<h1 align="center">Cloak</h1>

<p align="center">
  <strong>Your AI agent uses your API keys without ever seeing them.</strong>
</p>

<p align="center">
  <a href="https://github.com/cloakward/cloak/actions/workflows/ci.yml"><img src="https://github.com/cloakward/cloak/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/cloakward/cloak/attestations"><img src="https://slsa.dev/images/gh-badge-level3.svg" alt="SLSA L3"></a>
  <a href="https://github.com/cloakward/cloak/releases"><img src="https://img.shields.io/badge/cosign-verified-2ea44f?logo=sigstore" alt="cosign verified"></a>
  <a href="https://www.npmjs.com/package/@cloak-ward/mcp"><img src="https://img.shields.io/npm/v/@cloak-ward/mcp.svg?label=%40cloak-ward%2Fmcp" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="Apache-2.0"></a>
</p>

<p align="center">
  <img src="docs/cloak-demo.gif" width="720" alt="Cloak demo">
</p>

Pasting your API key into an AI chat is the new `rm -rf /`. Once the model has it, the value has been logged, cached, and possibly trained on. Cloak is a local secrets daemon that lets your agent do its job (sign requests, call APIs, mint short-lived tokens) without the keys ever entering the model's context.

## Install

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

Other ways to install: `npm install -g @cloak-ward/mcp`, drag-and-drop [`Cloak.dxt`](https://github.com/cloakward/cloak/releases) for Claude Desktop, or build from source. Full options in [`docs/QUICKSTART.md`](docs/QUICKSTART.md).

## Why Cloak

- **Local first.** Your vault and daemon run on your machine. No cloud, no signups, no telemetry.
- **The model never sees plaintext.** Six action-shaped MCP tools. There is no `read_secret` and there will never be one.
- **Touch ID gated reveal.** Even you have to authenticate to decrypt. The biometric prompt fires inside the daemon, not the CLI, so a same-UID attacker who skips the CLI cannot skip the prompt.
- **24-word recovery seed.** Lose your passphrase, restore from a paper backup. Same idea as a hardware wallet.
- **Apple notarized.** Gatekeeper accepts on first launch. Cosign signatures and SLSA L3 provenance on every release if you want to verify.
- **Open source, Apache-2.0.** Read the code, build from source, change what you want.

## What it looks like

> **You:** How much have I spent on OpenAI this billing cycle?
>
> **Claude:** Let me check.
>
> _Calls `proxy_authenticated_http_request` against `api.openai.com/v1/usage`. Cloak attaches `OPENAI_API_KEY` server-side. The model never sees the value._
>
> **Claude:** You've used $47.83 of your $200 monthly limit (24%). Top models: gpt-4o at $31.20, gpt-4o-mini at $16.63. You're 6 days into the cycle, tracking to about $240/month if usage stays flat.

The key never entered the model's context. Cloak attached it, made the request, returned only the response body. The action is recorded with the secret name, target host, and a hash-chain link in `~/.local/share/cloak/audit.jsonl`. The value itself is not.

## Documentation

- **Quickstart** [`docs/QUICKSTART.md`](docs/QUICKSTART.md)
- **Architecture** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- **Threat model** [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- **MCP tool spec** [`docs/spec/mcp-tools.md`](docs/spec/mcp-tools.md)
- **FAQ** [`docs/FAQ.md`](docs/FAQ.md)

## License

Apache-2.0. See [`LICENSE`](LICENSE).
