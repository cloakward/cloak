# Cloak Quickstart (v0.1, macOS)

> v0.1 is macOS-only. Linux/Windows compile but key OS integrations (Keychain, Touch ID, peer auth) are stubs in this drop.

## 1. Build

```sh
git clone <this-repo>
cd cloak
cargo build --release
cd packages/cloak-mcp && bun install && bun build src/server.ts --compile --outfile dist/cloak-mcp
```

Binaries:
- `target/release/cloak` — CLI
- `target/release/cloakd` — daemon
- `packages/cloak-mcp/dist/cloak-mcp` — MCP server (single binary)

## 2. Install the daemon (launchd, per-user)

```sh
./scripts/install-launchd.sh
launchctl list | grep cloakd     # should show running
tail -f ~/Library/Logs/cloak/cloakd.err.log
```

## 3. Initialize the vault

```sh
cloak init                  # prompts for passphrase, autotunes Argon2id
cloak status                # vault path, record count, KDF params
```

## 4. Add and reveal a secret

```sh
cloak add OPENAI_API_KEY    # paste secret on the prompt (echo off)
cloak list                  # OPENAI_API_KEY (no value)
cloak show OPENAI_API_KEY   # Touch ID prompt → prints to TTY
```

`cloak show` only writes to a TTY by default. To pipe, you must add `--allow-redirect` (and accept that it leaves your shell history).

## 5. Wire into Claude Desktop

Add to your `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cloak": {
      "command": "/absolute/path/to/cloak/packages/cloak-mcp/dist/cloak-mcp"
    }
  }
}
```

Restart Claude Desktop. In a new chat, ask:

> "What secrets do I have in my Cloak vault?"

You'll see a `list_secret_names` tool call. The model will receive names and metadata only — never values.

To make an authenticated call without ever handling the key:

> "Send a GET to https://api.openai.com/v1/models using my OPENAI_API_KEY."

The model will call `proxy_authenticated_http_request`. The daemon attaches the key, makes the request, returns status + body. The key never leaves the daemon.

## 6. Inspect the audit log

```sh
cloak audit tail -n 20
cloak audit verify ~/Library/Application\ Support/cloak/audit.jsonl
```

## What's deliberately not here yet

- Linux / Windows installers.
- BIP-39 recovery (`cloak recover --from-words`).
- Automated secret rotation (`cloak rotate NAME`).
- `.env` import.
- Signed release artifacts.

See `CHANGELOG.md` for the full deferred list.
