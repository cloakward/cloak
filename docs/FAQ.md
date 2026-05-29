# FAQ

### Why does macOS say "Varun Menon will be running in your background"?

macOS is showing the Developer ID certificate subject, not a separate Cloak display name. Current signed downloads use an individual Apple Developer ID, so Gatekeeper or Background Items may show "Varun Menon". A product/company signer name requires an Apple organization account with a registered legal entity. Until Cloak has that account, the personal name on signed/notarized macOS downloads is expected.

If you'd rather not see my name, build from source. Self-built binaries are ad-hoc-signed and have no developer identity attached.

### Why is `cloak add` not showing what I type?

By design. Same pattern as `sudo` or `ssh-keygen`: echo is off so a screen recorder or shoulder surfer cannot catch the value. The CLI prints a reminder above the prompt to make this less surprising.

### Why does it ask for a passphrase instead of Touch ID?

The passphrase is the cryptographic secret. It feeds Argon2id alongside the OS-keychain pepper to derive the master key. Touch ID is a presence check on top, not a key by itself.

`cloak unlock` unlocks the daemon once per daemon start so MCP tools can operate without re-sending the passphrase. `cloak show` still opens the vault directly today, so it asks for the passphrase and then performs the Touch ID / polkit presence check. A fully Touch-ID-gated unlock that trusts the macOS Keychain to hold unlock material is still future work.

### Can I run it without trusting your binaries at all?

Yes, two ways:

1. **Build from source.** `cargo build --release --workspace` produces ad-hoc-signed binaries with no developer identity attached. Same code, your build.
2. **Verify the signed releases.** Release tags built by the current workflow ship cosign keyless signatures and SLSA L3 provenance for tarballs, `sha256sums.txt`, and macOS `.dxt` packages. Older preview `.dxt` assets may be unsigned; require matching `.sig` / `.cert` files and a SLSA subject before trusting them.

### Does Cloak phone home, telemetry, anything?

No analytics, version-check pings, usage reporting, or Cloak-owned cloud calls. `cloakd` makes outbound network calls only when your agent invokes a networked tool. `proxy_authenticated_http_request` is constrained by your policy file's host allowlist. `mint_short_lived_token` is governed by tool/secret policy and currently calls AWS STS for the requested/default region; host allowlists do not apply to that STS call.

### What happens if I lose my passphrase?

If you wrote down your 24-word recovery seed at vault creation: run `cloak restore`, type the seed, set a new passphrase. Done.

If you lost both the passphrase and the seed: every secret in the vault is permanently unrecoverable. Cloak does not keep a copy of either. This is the same threat model as a hardware wallet.

### Does Cloak work with my MCP client?

Out of the box: Claude Desktop, Claude Code, Cursor, Windsurf, Continue.dev, Zed, Codex. The setup wizard auto-detects whichever ones you have installed and wires them up.

If your client supports MCP and isn't on the list, point it at the `cloak-mcp` binary as a stdio MCP server. The protocol is standard.

### What's the difference between `cloak` and `cloakd`?

`cloakd` is the daemon. It owns the vault, holds the master key in memory after you unlock, and performs every privileged action. It listens on a Unix domain socket.

`cloak` is the CLI. It talks to `cloakd` over the socket for daemon-managed operations, and reads the vault file directly for things like `cloak add`. It's the only path that ever reveals plaintext to the user, gated behind Touch ID or polkit.

`cloak-mcp` is a separate Bun-compiled binary your AI agent talks to. It translates MCP tool calls into IPC requests against `cloakd`. It imports zero HTTP clients; the daemon owns all outbound network.

### Is Windows supported?

Not in the current release artifacts. Windows support and SignPath OV signing are tracked in [`#2`](https://github.com/cloakward/cloak/issues/2).

### How do I uninstall?

```sh
cloak panic                # locks the vault and stops the daemon
brew uninstall cloak
rm -rf ~/Library/Application\ Support/cloak  # or ~/.local/share/cloak on Linux
```

`cloak panic` is also the right command if you suspect compromise: it stops the daemon, revokes live sessions, and prints a rotation worksheet. It does not uninstall the LaunchAgent/systemd unit; use your package manager or remove the service file separately when uninstalling.
