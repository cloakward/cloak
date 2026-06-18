# Cloak Quickstart

This guide gets you from "nothing installed" to "an MCP client can use a stored API key without seeing the raw stored value."

Supported release artifacts today: macOS arm64/x64 and Linux. Windows installers are not part of the current release yet ([issue #2](https://github.com/cloakward/cloak/issues/2)).

## 1. Install

On macOS arm64/x64 and Linux x64 glibc:

```sh
brew install cloakward/cloak/cloak
cloak setup
```

`cloak setup` installs and starts the daemon, initializes the vault if needed, and helps register supported clients such as Claude Desktop, Claude Code, Cursor, Windsurf, Continue.dev, Zed, and Codex.

For Linux x64 musl or Linux arm64, download the verified release tarball for your target from [GitHub Releases](https://github.com/cloakward/cloak/releases). Linux x64 musl and Linux arm64 currently ship the CLI and daemon only; native `cloak-mcp` packages are built for macOS arm64/x64 and Linux x64 glibc.

The container image is published as `ghcr.io/cloakward/cloakd:latest`. Treat it as daemon/operator packaging, not the default laptop install path. Container deployments have weaker keychain and peer-auth assumptions than a single-user laptop; read the [container deployment section](THREAT_MODEL.md#container-deployment-ghcriocloakwardcloakd) before relying on it for sensitive workflows.

## 2. Create And Back Up The Vault

If `cloak setup` did not already initialize the vault, run:

```sh
cloak init
```

`cloak init` prints a 24-word recovery seed exactly once. Write it down on paper and store it offline. If you lose both the passphrase and the seed, Cloak cannot recover your secrets.

Confirm the seed while you still have it in front of you:

```sh
cloak backup verify
```

## 3. Add A Secret

```sh
cloak add OPENAI_API_KEY    # paste on the hidden prompt
cloak list                  # names only, never values
cloak show OPENAI_API_KEY   # local user-presence prompt, then prints to TTY
```

`cloak show` only writes to a TTY by default. To pipe it, you must explicitly
add `--allow-redirect`; then the output can be captured by whatever pipeline,
terminal logger, clipboard tool, or child process you chose.

## 4. Unlock The Daemon

The CLI can edit the vault directly, but MCP tools talk to the background daemon. Unlock the daemon once per daemon start:

```sh
cloak unlock
cloak status
```

`cloak status` shows vault metadata and `daemon state: locked` / `unlocked` when the daemon is reachable. If you skip this step, MCP calls that need a secret return `vault-locked`.

## 5. Allow The API Host

The API proxy is default-deny: every secret starts blocked. Allow a secret to reach a host with one command. It applies live, with no daemon restart and no re-unlock:

```sh
cloak allow OPENAI_API_KEY api.openai.com
```

Check what each secret can reach, or revoke a host:

```sh
cloak policy
cloak deny OPENAI_API_KEY api.openai.com
```

Prefer to edit the file? `cloak doctor` prints the policy path; each secret is one `[[secrets]]` block with an `allowed_hosts` list. Changes via `cloak allow`/`deny` apply live; after a manual edit, run `cloak daemon restart` to pick it up.

## 6. Use It From Claude Desktop

If `cloak setup` registered Claude Desktop, restart Claude Desktop and open a new chat.

If you prefer to wire it manually, add this to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cloak": {
      "command": "/opt/homebrew/bin/cloak-mcp"
    }
  }
}
```

Adjust the path if `which cloak-mcp` points somewhere else.

In a new chat, ask:

> What secrets do I have in my Cloak vault?

You should see a `list_secret_names` tool call. The model receives names and metadata only, not secret values.

Then try an authenticated request:

> Send a GET to https://api.openai.com/v1/models using my OPENAI_API_KEY.

Cloak policy-checks the host, reads the vault inside the daemon, attaches the credential server-side, makes the request, strips the auth header it attached, and returns the upstream status, headers, and body to the MCP client.

Only allow hosts you trust. Cloak cannot prove a remote API will never echo transformed credentials or unrelated sensitive data.

## Claude Desktop `.dxt` On macOS

The signed `Cloak-*.dxt` packages install the `cloak-mcp` shim only. They do not install the vault CLI or the `cloakd` daemon.

Use this order:

1. Install the full CLI + daemon first (`brew install ...`, then `cloak setup`).
2. Run `cloak daemon start` and `cloak unlock`.
3. Drag the verified `Cloak-*.dxt` into Claude Desktop.
4. Restart Claude Desktop.

The `.dxt` first-run flow intentionally does not initialize the vault inside Claude Desktop, because the one-time recovery seed needs to be displayed and verified safely in a terminal.

## Verify A Release

Stable releases include checksums, cosign signatures/certificates, SLSA provenance, and notarized macOS binaries. Verification commands are in [docs/RELEASE.md](RELEASE.md).

For the security boundary, read [docs/THREAT_MODEL.md](THREAT_MODEL.md) and [docs/SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md).

## Linux Notes

Linux daemon peer authentication requires Linux 6.5+ for `SO_PEERPIDFD`. Older kernels fail closed before issuing CLI or MCP session tokens.

On desktop Linux, Cloak stores its pepper in freedesktop Secret Service. `cloak show` uses polkit for the local user-presence prompt (`dev.cloak.show-secret`). Install the packaged policy file when using a tarball or source build:

```sh
# Homebrew on Linux:
sudo install -Dm644 "$(brew --prefix cloak)/share/cloak/dev.cloak.policy" \
  /usr/share/polkit-1/actions/dev.cloak.policy

# Release tarball, run from the extracted cloak-<version>-<target> directory:
sudo install -Dm644 share/polkit-1/actions/dev.cloak.policy \
  /usr/share/polkit-1/actions/dev.cloak.policy

# Source checkout:
sudo install -Dm644 scripts/polkit/dev.cloak.policy \
  /usr/share/polkit-1/actions/dev.cloak.policy
```

On headless Linux without a Secret Service agent, set a file-backed pepper in the user service:

```sh
mkdir -p ~/.config/systemd/user/cloakd.service.d ~/.config/cloak
cat > ~/.config/systemd/user/cloakd.service.d/headless-pepper.conf <<'EOF'
[Service]
Environment=CLOAK_PEPPER_FILE=%h/.config/cloak/pepper
EOF

systemctl --user daemon-reload
systemctl --user restart cloakd.service
```

Cloak creates the pepper file on first use with mode `0600`. Back it up separately from the vault. Without that pepper, a copied vault cannot be decrypted.

## Manual Daemon Setup

`cloak setup` is the recommended path. For source builds or custom service managers, the manual commands are:

### macOS launchd

```sh
cloak daemon install --launchd
cloak daemon start
launchctl print "gui/$(id -u)/dev.cloak.cloakd"
tail -f ~/Library/Logs/cloak/cloakd.err.log
```

### Linux systemd user

Install the binaries somewhere on your user `PATH`, then create a user service:

```sh
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/cloakd.service <<'EOF'
[Unit]
Description=Cloak daemon
After=default.target

[Service]
Type=simple
ExecStart=%h/.local/bin/cloakd
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now cloakd.service
journalctl --user -u cloakd -f
```

## Build From Source

Use source builds when you want the most direct local audit path:

```sh
git clone https://github.com/cloakward/cloak
cd cloak
./scripts/prepare-libsodium-dist.sh
SODIUM_DIST_DIR="$PWD/.cargo/libsodium-dist" cargo build --release --workspace
cd packages/cloak-mcp && bun install --frozen-lockfile && bun run build
cd ../..
mkdir -p "$HOME/.local/bin"
install -m 755 target/release/cloak "$HOME/.local/bin/cloak"
install -m 755 target/release/cloakd "$HOME/.local/bin/cloakd"
install -m 755 packages/cloak-mcp/dist/cloak-mcp "$HOME/.local/bin/cloak-mcp"
```

Keep `cloak`, `cloakd`, and `cloak-mcp` installed in the same directory. The production daemon pins trusted client binaries by hash at startup and trusts the `cloak-mcp` sibling next to `cloakd`; pointing an MCP client at a different build output can fail peer authentication.

## Recovery And Upgrade Tasks

If you lose your passphrase but still have the 24-word recovery seed:

```sh
cloak restore
```

Cloak prompts for the seed and a new passphrase, then re-wraps the existing vault key. The old passphrase stops working.

If you are upgrading from a build that stored only the rollback counter in the OS keychain, Cloak fails closed instead of silently trusting that legacy mirror. After reviewing and trusting the current vault file, adopt its state-hash mirror explicitly:

```sh
cloak rollback adopt-state --yes
```

If an existing install has a non-empty `audit.jsonl` from before external audit-head anchoring existed, new writes fail closed until you review the log and explicitly adopt its current head:

```sh
tail -n 20 ~/Library/Application\ Support/cloak/audit.jsonl
cloak audit adopt-head --yes
cloak audit verify
```

## Audit Log

The hash-chained JSONL audit log lives at:

- macOS: `~/Library/Application Support/cloak/audit.jsonl`
- Linux: `~/.local/share/cloak/audit.jsonl`

Check it directly or verify the chain:

```sh
tail -n 20 ~/Library/Application\ Support/cloak/audit.jsonl
cloak audit verify
```

## Not Here Yet

- Windows installers.
- Automated secret rotation (`cloak rotate NAME`).
- Production `.pkg` / `.dmg` installers with offline-stapled notarization tickets.

See [CHANGELOG.md](../CHANGELOG.md) for the full deferred list.
