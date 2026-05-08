# Cloak Quickstart (v1.0.0, macOS)

> v1.0.0 ships macOS + Linux. Windows is deferred to v1.0.1
> ([issue #3](https://github.com/cloakward/cloak/issues/3)). On Linux the
> desktop pepper uses freedesktop Secret Service (W7) and `cloak show`
> gates the reveal on polkit (`dev.cloak.show-secret`; install
> `scripts/polkit/dev.cloak.policy` under
> `/usr/share/polkit-1/actions/`). The walkthrough below is
> macOS-flavored — swap `~/Library/Application Support` for the XDG
> equivalent on Linux.

## Gatekeeper note (macOS)

v1.0.0 release binaries are signed with a Developer ID Application certificate, notarized by Apple, and stapled. Gatekeeper accepts them on first launch with no `xattr` dance. Every release is also cosign-signed with SLSA L3 provenance, which lets you verify the binary is the exact artifact CI built; notarization adds Apple's pre-execution scan on top of that.

If you build from source there is no Gatekeeper friction either — your local toolchain produces an ad-hoc-signed binary that runs immediately.

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

`cloak init` prints a 24-word BIP-39 recovery seed exactly **once**.
Write it down on paper and store it offline. If you lose your passphrase,
the seed is the only path back to your secrets — Cloak does not keep a
copy. Confirm you wrote it down correctly with `cloak backup verify`.

## 3b. If you lose your passphrase

If you still have the 24-word recovery seed you wrote down at vault
creation, run `cloak restore`:

```sh
cloak restore               # prompts for the 24 words + a NEW passphrase
```

Cloak re-derives the master key from the seed (BIP-39 standard
PBKDF2-HMAC-SHA512) and re-wraps it under your fresh passphrase. The
old passphrase is no longer valid. Your secrets are unchanged.

If you lose **both** the passphrase and the seed, every secret in the
vault is permanently unrecoverable — that is the design.

## 4. Add and reveal a secret

```sh
cloak add OPENAI_API_KEY    # paste secret on the prompt (echo off)
cloak list                  # OPENAI_API_KEY (no value)
cloak show OPENAI_API_KEY   # Touch ID prompt → prints to TTY
```

`cloak show` only writes to a TTY by default. To pipe, you must add `--allow-redirect` (and accept that it leaves your shell history).

## 5. Unlock the running daemon

`cloak init` / `cloak add` operate on the vault file directly. The running
`cloakd` (the process MCP talks to) keeps its master key in memory and
must be told the passphrase **once per `cloakd` start** — that is, after every
reboot, manual `launchctl unload/load`, or daemon crash:

```sh
cloak daemon-unlock              # prompts for the passphrase, pushes it
                                 # to the running cloakd over the UDS
```

The daemon stays unlocked for the rest of the session. `cloak status` will
show whether it's locked or unlocked. If you skip this step, MCP tool
calls that need to read a secret will return `vault-locked`.

## 6. Wire into Claude Desktop

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

## 7. Inspect the audit log

The hash-chained JSONL audit log lives at `~/Library/Application Support/cloak/audit.jsonl` (XDG equivalent on Linux). Tail it directly, or query it through the daemon via the MCP `tool.query_audit` surface:

```sh
tail -n 20 ~/Library/Application\ Support/cloak/audit.jsonl
```

## What's deliberately not here yet

- Linux / Windows installers.
- Automated secret rotation (`cloak rotate NAME`).
- `.env` import.
- Signed release artifacts.

See `CHANGELOG.md` for the full deferred list.
