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

## Verify your install

```
$ cloak doctor
[ok]   binary `cloak` on PATH      /opt/homebrew/bin/cloak
[ok]   binary `cloakd` on PATH     /opt/homebrew/bin/cloakd
[ok]   binary `cloak-mcp` on PATH  /opt/homebrew/bin/cloak-mcp
[ok]   daemon                      running, socket at ~/.cloak/sock
[ok]   vault                       unlocked, 3 secrets
[ok]   keychain pepper             present
[ok]   biometric                   Touch ID available
[ok]   policy file                 ~/.config/cloak/policy.toml
[ok]   Claude Desktop              registered
[ok]   Claude Code                 registered
[ok]   Cursor                      registered
```

Every tool call your agent makes lands in a hash-chained audit log. The note field never contains secret values.

```
$ tail -n 2 ~/.local/share/cloak/audit.jsonl
{"seq":42,"ts":"2026-05-08T19:14:08Z","tool":"tool.proxy_authenticated_http_request","secret":"OPENAI_API_KEY","target":"api.openai.com","result":"ok","peer":{"basename":"cloak-mcp","pid":74221},"prev_hash":"7c8f9a2b…"}
{"seq":43,"ts":"2026-05-08T19:14:11Z","tool":"tool.sign_request","secret":"AWS_ACCESS_KEY_ID","target":"sts.us-east-1.amazonaws.com","result":"ok","peer":{"basename":"cloak-mcp","pid":74221},"prev_hash":"a1b2c3d4…"}
```

## Documentation

- **Quickstart** [`docs/QUICKSTART.md`](docs/QUICKSTART.md)
- **Architecture** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- **Threat model** [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- **MCP tool spec** [`docs/spec/mcp-tools.md`](docs/spec/mcp-tools.md)
- **FAQ** [`docs/FAQ.md`](docs/FAQ.md)

## License

Apache-2.0. See [`LICENSE`](LICENSE).
