# Cloak Quickstart (v1.0, macOS)

> v1.0 ships macOS + Linux. Windows is deferred to v1.0.1
> ([issue #3](https://github.com/cloakward/cloak/issues/3)). On Linux the
> desktop pepper uses freedesktop Secret Service (W7) and `cloak show`
> gates the reveal on polkit (`dev.cloak.show-secret`; install
> `scripts/polkit/dev.cloak.policy` under
> `/usr/share/polkit-1/actions/`). The walkthrough below is
> macOS-flavored — swap `~/Library/Application Support` for the XDG
> equivalent on Linux.

## Gatekeeper note (macOS, unsigned dev builds)

Cloak v1.0 binaries are not Apple-notarized. After downloading a release artifact, macOS Gatekeeper will refuse to run it until you clear the quarantine attribute:

```sh
xattr -d com.apple.quarantine ./cloak ./cloakd ./cloak-mcp
```

Apple notarization is a v1.x deliverable. The cosign + SLSA L3 attestations on every release are sufficient to verify that the binary you have is the one CI built; notarization adds Apple's pre-execution scan on top of that. We chose to ship without notarization for v1.0 to avoid the Apple Developer Program enrollment and signing-cert renewal treadmill while the project is small.

If you build from source there is no Gatekeeper friction — your local toolchain produces an ad-hoc-signed binary that runs immediately.

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

## 5. Unlock the running daemon

`cloak init` / `cloak add` operate on the vault file directly. The running
`cloakd` (the process MCP talks to) keeps its master key in memory and
must be told the passphrase exactly once per boot:

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
