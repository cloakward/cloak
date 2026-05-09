# FAQ

### Why does macOS say "Varun Menon will be running in your background"?

That's me. Cloak v1.0 is signed with my individual Apple Developer ID, so any macOS surface that asks "do you trust this developer?" pulls my legal name from the cert. Apple Developer Program organization accounts (with a company name on the cert) require a D-U-N-S number and a registered legal entity, queued for v1.0.1.

If you'd rather not see my name, build from source. Self-built binaries are ad-hoc-signed and have no developer identity attached.

### Why is `cloak add` not showing what I type?

By design. Same pattern as `sudo` or `ssh-keygen`: echo is off so a screen recorder or shoulder surfer cannot catch the value. The CLI prints a reminder above the prompt to make this less surprising.

### Why does it ask for a passphrase instead of Touch ID?

The passphrase is the cryptographic secret. It feeds Argon2id alongside the OS-keychain pepper to derive the master key. Touch ID is a presence check on top, not a key by itself.

After the daemon is unlocked once per session, every reveal is gated by Touch ID with no passphrase prompt. A fully Touch-ID-gated unlock that trusts the macOS Keychain to hold the unlock material is a v1.0.1 opt-in.

### Can I run it without trusting your binaries at all?

Yes, two ways:

1. **Build from source.** `cargo build --release --workspace` produces ad-hoc-signed binaries with no developer identity attached. Same code, your build.
2. **Verify the signed releases.** Every release ships cosign keyless signatures and SLSA L3 provenance. You can confirm the published binaries match the exact CI run that built them.

### Does Cloak phone home, telemetry, anything?

No. cloakd makes zero outbound network calls except those your agent explicitly drives through `proxy_http` or `mint_token`, against the hosts your policy file allows. There is no analytics, no version-check ping, no usage reporting.

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

Not in v1.0. Windows + SignPath OV signing is v1.0.1 work. Track [`#2`](https://github.com/cloakward/cloak/issues/2).

### How do I uninstall?

```sh
cloak panic                # locks the vault and stops the daemon
brew uninstall cloak
rm -rf ~/Library/Application\ Support/cloak  # or ~/.local/share/cloak on Linux
```

`cloak panic` is also the right command if you suspect compromise: it tears everything down, zeroizes in-memory state, and removes the LaunchAgent.
