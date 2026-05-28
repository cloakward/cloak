# Cloak Quickstart (beta, macOS + Linux)

> Cloak is beta software. Source builds are the recommended install path
> until a production release tag has passed the full release gate. Windows
> is not part of the current release artifacts yet ([issue #3](https://github.com/cloakward/cloak/issues/3)).
> On Linux the desktop pepper uses freedesktop Secret Service and `cloak show`
> gates the reveal on polkit (`dev.cloak.show-secret`; install
> `scripts/polkit/dev.cloak.policy` under `/usr/share/polkit-1/actions/`).
> The walkthrough starts macOS-flavored; Linux systemd guidance follows.

## Gatekeeper note (macOS)

Production macOS tags cut by the current release workflow are hard-gated on
Developer ID signing and Apple notarization secrets. If those secrets are
missing, stable macOS rows fail rather than publishing unsigned tarballs.
Prerelease/fork preview builds may still be unsigned and can require
`xattr -d com.apple.quarantine` after download.

Bare command-line Mach-O binaries cannot be stapled in-place like `.pkg` or
`.dmg` bundles. The release workflow submits them to Apple's notary service;
Gatekeeper may need an online ticket lookup on first launch.

Release tags built by the current workflow are also cosign-signed and
SLSA-attested for tarballs, `sha256sums.txt`, and Claude Desktop `.dxt`
packages. Older preview `.dxt` files may not be covered; require matching
`.sig` / `.cert` files and a SLSA subject before treating a `.dxt` as verified.

If you build from source there is no Gatekeeper friction either — your local toolchain produces an ad-hoc-signed binary that runs immediately.

## 1. Build

```sh
git clone <this-repo>
cd cloak
cargo build --release --workspace
cd packages/cloak-mcp && bun install --frozen-lockfile && bun run build
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

## 2b. Install the daemon on Linux (systemd user)

Install the binaries somewhere on your user `PATH`:

```sh
install -Dm755 target/release/cloak ~/.local/bin/cloak
install -Dm755 target/release/cloakd ~/.local/bin/cloakd
install -Dm755 packages/cloak-mcp/dist/cloak-mcp ~/.local/bin/cloak-mcp
```

Install the polkit action so `cloak show` can perform a user-presence check:

```sh
sudo install -Dm644 scripts/polkit/dev.cloak.policy \
  /usr/share/polkit-1/actions/dev.cloak.policy
```

Create a per-user systemd unit:

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

On desktop Linux, leave `CLOAK_PEPPER_FILE` unset so Cloak uses
freedesktop Secret Service. On headless Linux without a Secret Service
agent, add a file-backed pepper override:

```sh
mkdir -p ~/.config/systemd/user/cloakd.service.d ~/.config/cloak
cat > ~/.config/systemd/user/cloakd.service.d/headless-pepper.conf <<'EOF'
[Service]
Environment=CLOAK_PEPPER_FILE=%h/.config/cloak/pepper
EOF

systemctl --user daemon-reload
systemctl --user restart cloakd.service
```

Cloak creates the pepper file on first use with mode `0600`; back it up
separately from the vault. Without that pepper, a copied vault cannot be
decrypted.

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
cloak show OPENAI_API_KEY   # Touch ID / polkit prompt, then prints to TTY
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

- Windows installers.
- Automated secret rotation (`cloak rotate NAME`).
- Production `.pkg` / `.dmg` with offline-stapled notarization tickets.
- Fully pinned-by-digest release infrastructure for every GitHub Action and
  Docker base image.

See `CHANGELOG.md` for the full deferred list.
