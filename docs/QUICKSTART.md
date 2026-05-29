# Cloak Quickstart (macOS + Linux)

> Cloak's stable macOS and Linux release artifacts are production-gated:
> CI, security scans, smoke tests, Apple signing/notarization, cosign/SLSA
> verification, downstream publish jobs, and published-artifact install
> checks must pass before a stable tag is recommended. Windows is not part
> of the current release artifacts yet ([issue #2](https://github.com/cloakward/cloak/issues/2)).
> On Linux the desktop pepper uses freedesktop Secret Service and `cloak show`
> gates the reveal on polkit (`dev.cloak.show-secret`; install the packaged
> `dev.cloak.policy` under `/usr/share/polkit-1/actions/`).
> Linux daemon peer-auth also requires Linux 6.5+ for `SO_PEERPIDFD`;
> older kernels fail closed before issuing CLI or MCP session tokens.
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
SLSA-attested for tarballs, `sha256sums.txt`, and macOS Claude Desktop `.dxt`
packages. Older preview `.dxt` files may not be covered; require matching
`.sig` / `.cert` files and a SLSA subject before treating a `.dxt` as verified.

If you build from source there is no Gatekeeper friction either — your local toolchain produces an ad-hoc-signed binary that runs immediately.

macOS trust surfaces such as Gatekeeper and Background Items show the
Developer ID certificate subject, not the package name. Current signed
downloads may therefore display the individual Developer ID name
"Varun Menon"; that is expected until Cloak uses an Apple organization
account.

## 1. Full install: CLI + daemon + MCP shim

On macOS arm64/x64 and Linux x64 glibc:

```sh
brew install cloakward/cloak/cloak
cloak setup
```

This installs `cloak`, `cloakd`, and `cloak-mcp`, then walks through vault
creation, daemon setup, and MCP-client registration. For Linux x64 musl or
Linux arm64, use the verified release tarball for your target from GitHub
Releases. Linux x64 musl and Linux arm64 currently ship the CLI and daemon
only; native `cloak-mcp` packages are built for macOS arm64/x64 and Linux x64
glibc.

## 1b. Build from source

```sh
git clone <this-repo>
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

Binaries:
- `$HOME/.local/bin/cloak` — CLI
- `$HOME/.local/bin/cloakd` — daemon
- `$HOME/.local/bin/cloak-mcp` — MCP server (single binary)

Keep all three installed in the same directory. The production daemon pins
trusted client binaries by hash at startup and trusts the `cloak-mcp` sibling
next to `cloakd`; pointing an MCP client at `packages/cloak-mcp/dist/cloak-mcp`
while the daemon runs from another install directory can fail peer auth.

## 1c. MCP shim only

Claude Desktop users on macOS can drag-and-drop a verified `Cloak-*.dxt` after
`cloak` and `cloakd` are already installed. The `.dxt` installs the
`cloak-mcp` shim only. It does not install the vault CLI or daemon. The
`.dxt` first-run flow never initializes the vault from inside Claude
Desktop; it shows setup guidance and requires you to run `cloak setup` in a
terminal so the one-time recovery seed can be displayed and verified safely.
Then run `cloak daemon start` and `cloak unlock`, and restart Claude Desktop.

npm distribution is paused until it can ship audited native `cloak-mcp`
binaries per supported platform. Use Homebrew, release tarballs, or signed
macOS `.dxt` assets for Claude Desktop installs.

## 2. Install the daemon manually (source builds, macOS launchd)

```sh
cloak daemon install --launchd
cloak daemon start
launchctl print "gui/$(id -u)/dev.cloak.cloakd"
tail -f ~/Library/Logs/cloak/cloakd.err.log
```

## 2b. Install the daemon manually on Linux (systemd user)

Install the binaries somewhere on your user `PATH`:

```sh
install -Dm755 target/release/cloak ~/.local/bin/cloak
install -Dm755 target/release/cloakd ~/.local/bin/cloakd
install -Dm755 packages/cloak-mcp/dist/cloak-mcp ~/.local/bin/cloak-mcp
```

Install the polkit action so `cloak show` can perform a user-presence check:

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
cloak unlock                     # prompts for the passphrase, pushes it
                                 # to the running cloakd over the UDS
```

`cloak daemon-unlock` is the same command under its older name. The daemon
stays unlocked until it exits or receives `vault.lock`. `cloak status`
prints vault-file metadata plus `daemon state: locked` / `unlocked` when
the daemon is reachable; `cloak daemon status` only reports whether the
background process is running. If you skip this step, MCP tool calls that
need to read a secret will return `vault-locked`.

## 6. Wire into Claude Desktop

Add to your `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cloak": {
      "command": "/Users/YOU/.local/bin/cloak-mcp"
    }
  }
}
```

Restart Claude Desktop. In a new chat, ask:

> "What secrets do I have in my Cloak vault?"

You'll see a `list_secret_names` tool call. The model will receive names and metadata only — never values.

To make an authenticated call without ever handling the stored key:

> "Send a GET to https://api.openai.com/v1/models using my OPENAI_API_KEY."

The starter policy is default-deny. Before that prompt can succeed, edit
the policy file, uncomment or add an `OPENAI_API_KEY` rule that allows
`api.openai.com`, then restart and unlock the daemon. `cloak doctor` prints
the exact policy path; by default it is
`~/Library/Application Support/cloak/policy.toml` on macOS and
`~/.config/cloak/policy.toml` on Linux:

```toml
[[secrets]]
name = "OPENAI_API_KEY"

[secrets.tools.proxy_authenticated_http_request]
allowed_hosts = ["api.openai.com"]
```

```sh
cloak daemon restart
cloak unlock
```

The model will call `proxy_authenticated_http_request`. The daemon attaches the stored key, makes the request, and returns the upstream status, headers, and body to the MCP client. Cloak strips the auth header it attached, but it does not scrub arbitrary upstream responses; only allow hosts you trust not to echo credentials.

If you use `mint_short_lived_token`, the returned token is intentionally sent to the MCP client. It is not the long-lived parent secret, but it is still a credential until it expires.

## 7. Upgrade legacy rollback mirrors

If you are upgrading from a build that stored only the rollback counter in the
OS keychain, Cloak fails closed instead of silently trusting that legacy mirror.
After you have reviewed and trust the current vault file, adopt its state-hash
mirror explicitly:

```sh
cloak rollback adopt-state --yes
```

## 8. Inspect the audit log

The hash-chained JSONL audit log lives at `~/Library/Application Support/cloak/audit.jsonl` (XDG equivalent on Linux). Tail it directly, or query it through the daemon via the MCP `tool.query_audit` surface:

```sh
tail -n 20 ~/Library/Application\ Support/cloak/audit.jsonl
cloak audit verify
```

If you are upgrading an existing install that already has a non-empty
`audit.jsonl` from before external audit-head anchoring existed, new writes
fail closed until you review the log and explicitly adopt its current head.
The adopt command recomputes and verifies the hash chain before seeding the
external anchor:

```sh
tail -n 20 ~/Library/Application\ Support/cloak/audit.jsonl
cloak audit adopt-head --yes
cloak audit verify
```

## What's deliberately not here yet

- Windows installers.
- Automated secret rotation (`cloak rotate NAME`).
- Production `.pkg` / `.dmg` with offline-stapled notarization tickets.

See `CHANGELOG.md` for the full deferred list.
