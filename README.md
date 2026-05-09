<h1 align="center">Cloak</h1>

<p align="center">
  <strong>An MCP-native secrets vault. Your AI agent uses your API keys without ever seeing them.</strong>
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

Pasting `OPENAI_API_KEY` into a chat is the new `rm -rf /`. Once the model has it, it has been logged, cached, and possibly trained on. Cloak is a local secrets daemon that lets your AI agent perform privileged actions (signing requests, calling APIs, minting STS tokens) without the underlying keys ever entering the model's context.

## Install

### Homebrew (macOS / Linux)

```sh
brew install cloakward/cloak/cloak
cloak setup
```

### npm (cross-platform shim)

```sh
npm install -g @cloak-ward/mcp
cloak setup
```

### From source (no developer name on the binaries)

```sh
git clone https://github.com/cloakward/cloak && cd cloak
brew install libsodium bun
cargo build --release --workspace
./target/release/cloak setup
```

### Drag-and-drop (Claude Desktop)

Download `Cloak-1.0.0-<platform>.dxt` from the [latest release](https://github.com/cloakward/cloak/releases) and drag it onto Claude Desktop's **Settings → Extensions** panel. The wizard runs in a native dialog. Windows `.dxt` is v1.0.1 work.

### Then

```sh
cloak add OPENAI_API_KEY               # input is hidden as you type
cloak list                             # see what's in the vault
cloak run -- python my_script.py       # inject as env vars, biometric gated
```

The `setup` wizard takes about 60 seconds and auto-detects Claude Desktop, Claude Code, Cursor, Windsurf, Continue.dev, Zed, and Codex. Open any of them after setup and they route through Cloak.

## How it works

Three processes, one trust boundary.

```
              ┌──────────────────┐         ┌──────────────────┐
              │  Claude Desktop  │         │     terminal     │
              │  / Claude Code   │         │       user       │
              └────────┬─────────┘         └────────┬─────────┘
                       │ MCP / stdio                │ exec
                       ▼                            ▼
              ┌──────────────────┐         ┌──────────────────┐
              │    cloak-mcp     │         │      cloak       │
              │   (Bun, TS)      │         │      (Rust)      │
              │  zero HTTP imps  │         │   library + IPC  │
              └────────┬─────────┘         └────────┬─────────┘
                       │ length-prefixed JSON over UDS, peer-auth'd
                       ▼                            ▼
                              ┌─────────────────┐
                              │     cloakd      │
                              │     (Rust)      │
                              │ • libsodium     │
                              │ • SQLite WAL    │
                              │ • policy + audit│
                              │ • reqwest+rustls│
                              └────────┬────────┘
                                       │
                                       ▼  AEAD-sealed records
                              ┌─────────────────┐
                              │   vault.cloak   │
                              └─────────────────┘
```

- **`cloakd`** owns the vault. Rust, libsodium, SQLite WAL, Argon2id keyed mode. The only process that ever holds the master key in memory.
- **`cloak`** is the CLI. The only path that ever returns plaintext, gated behind Touch ID on macOS or polkit on Linux. Refuses by default over SSH.
- **`cloak-mcp`** is the MCP server your agent talks to. Six action-shaped tools, none of which return plaintext: `sign_request`, `proxy_authenticated_http_request`, `mint_short_lived_token`, `list_secret_names`, `get_secret_metadata`, `query_audit`.

There is no `read_secret` tool. The agent says "POST to api.openai.com" and the daemon does the privileged operation; the agent only sees the response. A prompt injection that tries calling `proxy_http` with a malicious URL gets blocked by the policy's `allowed_hosts` before any decryption happens.

## What ships in v1.0

| Area | What you get |
|---|---|
| **Crypto** | libsodium-only. XChaCha20-Poly1305-IETF AEAD, Argon2id keyed mode with autotune, per-record subkeys, `Secret<T>` zeroize-on-drop. |
| **Vault** | SQLite WAL, STRICT tables, master-key wrap with AAD, monotonic rollback counter mirrored to OS keychain. |
| **Recovery** | BIP-39 24-word seed, displayed once at init, second master-key wrap (PBKDF2-HMAC-SHA512). |
| **Reveal** | Server-side biometric inside cloakd. The daemon ignores any client-supplied "user already approved" flag. |
| **Audit** | Hash-chained JSONL, RFC 8785 canonical, atomic-append, tamper-evident. `audit.verify` rejects mutated, deleted, or reordered lines. |
| **Policy** | TOML DSL with default-deny, per-secret rules, glob matching, `allowed_hosts`, token-bucket rate limit. |
| **Distribution** | Apple-notarized macOS binaries, cosign keyless signatures, SLSA L3 provenance on every release. |
| **Clients** | Claude Desktop, Claude Code, Cursor, Windsurf, Continue.dev, Zed, Codex. |

Windows is v1.0.1. SignPath OV signing follows it. Full line-by-line in [`CHANGELOG.md`](CHANGELOG.md).

## Threat model

The full model is in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) with file-line citations for every defense. The five threats Cloak actually defends against:

- **A1.** Compromised LLM or prompt injection issuing arbitrary tool calls
- **A2.** Untrusted local process at the same UID
- **A3.** Vault-file thief with file-only access
- **A8.** PID-recycle attack against the daemon socket
- **A9.** Same-UID attacker bypassing the CLI to skip the biometric prompt

Three residual risks Cloak does NOT close yet (no certificate pinning on outbound HTTP, no swap-disable on cloakd, no fuzz harness on the IPC parser) are listed honestly in the threat model rather than papered over.

## FAQ

<details>
<summary><strong>Why does macOS say "Varun Menon will be running in your background"?</strong></summary>

That's me. Cloak v1.0 is signed with my individual Apple Developer ID, so any macOS surface that asks "do you trust this developer?" pulls my legal name from the cert. Apple Developer Program organization accounts (with a company name on the cert) require a D-U-N-S number and a registered legal entity, queued for v1.0.1. If you'd rather not see my name, the **From source** install above produces ad-hoc-signed binaries with no developer identity attached.

</details>

<details>
<summary><strong>Why is <code>cloak add</code> not showing what I type?</strong></summary>

By design. Same pattern as `sudo` or `ssh-keygen`: echo is off so a screen recorder or shoulder surfer cannot catch the value. The CLI prints a reminder above the prompt to make this less surprising.

</details>

<details>
<summary><strong>Why does it ask for a passphrase instead of Touch ID?</strong></summary>

The passphrase is the cryptographic secret. It feeds Argon2id alongside the OS-keychain pepper to derive the master key. Touch ID is a presence check on top, not a key by itself. After the daemon is unlocked once per session, every reveal is gated by Touch ID with no passphrase. A fully Touch-ID-gated unlock that trusts the macOS Keychain to hold the unlock material is a v1.0.1 opt-in.

</details>

<details>
<summary><strong>Can I run it without trusting your binaries at all?</strong></summary>

Yes. Use the **From source** install above. Or verify the signed releases yourself: every release ships cosign keyless signatures and SLSA L3 provenance, so you can confirm the published binaries match the exact CI run that built them.

</details>

<details>
<summary><strong>Does Cloak phone home, telemetry, anything?</strong></summary>

No. cloakd makes zero outbound network calls except those your agent explicitly drives through `proxy_http` or `mint_token`, against the hosts your policy file allows. There is no analytics, no version-check ping, no usage reporting.

</details>

## Documentation

- [`docs/QUICKSTART.md`](docs/QUICKSTART.md) walks the first run with screenshots
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) covers the three-process layout, IPC contract, and AAD bindings
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) lists every adversary, defense, and residual risk
- [`docs/SECURITY_INVARIANTS.md`](docs/SECURITY_INVARIANTS.md) gives the file-line backing for each invariant
- [`docs/IPC_WIRE.md`](docs/IPC_WIRE.md) is the frozen wire-format contract
- [`docs/spec/mcp-tools.md`](docs/spec/mcp-tools.md) is the locked JSON Schema for the six MCP tools

## License

Apache-2.0. See [`LICENSE`](LICENSE).
