# Cloak Threat Model (v1.0)

> This document describes what Cloak defends against, what it does not,
> and the trust assumptions underpinning each defense. It enumerates the
> primary attacker capabilities; an exhaustive defense-strength matrix
> with 15+ enumerated capabilities remains a v1.x deliverable.

## Assets, by sensitivity

| Tier | Asset | Where it lives |
|---|---|---|
| P0 | Vault master key | Memory of `cloakd` only. Wrapped at rest. |
| P0 | Long-lived secrets (API keys, OAuth tokens, DB URLs, SSH keys) | SQLite vault, AEAD-sealed per record. Plaintext only inside `cloakd` memory during a single operation. |
| P1 | Pepper | macOS Keychain (system-keychain item, ACL-restricted to `cloakd` codesig). On Linux: freedesktop Secret Service (GNOME Keyring / KWallet) via D-Bus (W7). `CLOAK_PEPPER_FILE` 0600 escape hatch for headless environments. |
| P1 | Recovery seed | Shown once at `init`; never persisted by `cloakd`. |
| P2 | Audit log | Hash-chained JSONL. Tamper-evident; never contains secret values. |
| P2 | Policy file | `~/.config/cloak/policy.toml`. World-readable is acceptable. |
| P3 | Session tokens | In-memory only. Invalidated on peer exit. |

## Adversaries we defend against

| Adversary | Capability | Mitigation in v1.0 |
|---|---|---|
| **A1 — Compromised LLM / prompt injection** | Issues arbitrary tool calls; reads any output the model receives | (a) MCP surface has no plaintext-reveal tool. (b) `proxy_http` enforces `allowed_hosts`. (c) Audit log records every privileged call. (d) `mint_short_lived_token` returns a derivative, not the parent. |
| **A2 — Untrusted local process (same UID)** | Connects to the daemon socket, reads files in `~/Library` | (a) Socket mode 0600 + UID check. (b) Peer-credential auth: PID + code-signature must match an allowlisted binary. (c) Vault file is AEAD-sealed even if read. |
| **A3 — Vault-file thief (different UID, file-only access)** | Steals `vault.cloak` from a backup or shared filesystem | (a) Argon2id keyed mode: passphrase is HMAC'd with a pepper from the OS keychain *before* KDF. Without the pepper, brute-force is infeasible even with weak passphrases. (b) AEAD tag on every record + master-key wrap. |
| **A4 — Network attacker (TLS)** | MITM on the daemon's outbound HTTP | (a) reqwest + rustls + system root store; no http://; no redirects to disallowed hosts. (b) Certificate pinning is **not** in v1.0 and is documented as a residual risk. |
| **A5 — Memory dump of `cloakd`** | Postmortem core, swap, hibernate | (a) `Secret<T>` zeroize-on-drop on every secret-typed value. (b) Master key kept only when unlocked; `cloak lock` zeroizes. (c) Swap-disable is **not** done in v1.0; users on shared servers should disable swap or use full-disk encryption. |
| **A6 — Tamper with vault file at rest** | Flip bytes in salt, ciphertext, header | AEAD tag detects any byte flip; typed `Error::Aead` (no panic). |
| **A7 — Rollback to earlier vault state** | Restore an older `vault.cloak` to undo a rotation | Monotonic counter committed to the macOS Keychain (separate item). On unlock, the counter must be ≥ the stored value, else `Error::VaultRollbackDetected`. |
| **A8 — PID recycle attack** | Reuse a freed PID to impersonate a trusted peer | macOS: at handshake `cloakd` calls `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)` to capture the peer's 32-byte `audit_token_t` (which carries the kernel's non-recycling pidversion in `val[7]`) and stores it in the `SessionRecord`; every subsequent request constant-time-compares the stored bytes via `subtle::ConstantTimeEq`. In parallel, a per-connection `kqueue` watcher armed with `EVFILT_PROC | NOTE_EXIT` (wrapped in `tokio::io::unix::AsyncFd`) revokes every session bound to the connection the instant the kernel reports the peer has exited, closing the PID-recycle window before any other process can inherit the freed PID. |

## What Cloak **does not** defend against (honest list)

- **Root / kernel-level local attacker.** Any process with root on the user's machine can read `cloakd`'s memory or substitute its binary. This is out of scope.
- **Compromised libsodium build.** We trust the upstream libsodium static binary we link.
- **Macros / shell aliases that wrap `cloak show`.** A user who pipes `cloak show` to a clipboard manager or a script that exfiltrates is opting into that risk.
- **The model's *output* containing secret material the user pastes back in.** If the user pastes a secret into a Claude prompt, Cloak cannot help. Cloak's value is making that paste unnecessary.
- **macOS Gatekeeper notarization.** v1.0 binaries are not Apple-notarized. Users must run `xattr -d com.apple.quarantine`. Notarization is a v1.x deliverable; cosign keyless + SLSA L3 provenance ship with v1.0 and are sufficient to verify the binary is the artifact CI built (`docs/RELEASE.md`).
- **Cross-platform parity.** v1.0 ships macOS + Linux. Windows is deferred to v1.0.1 ([issue #3](https://github.com/cloakward/cloak/issues/3)). On Linux the keychain pepper is real (W7 freedesktop Secret Service) and the user-presence gate is enforced via polkit (`dev.cloak.show-secret`, default policy `auth_self_keep`); when no polkit agent is registered, `cloak show` fails closed unless the user passes `--no-biometric`.
- **Linux desktop pepper via Secret Service.** v1.0 stores the pepper as a libsecret item in the user's default (or `login`) collection. A malicious local app running as the same UID can call `org.freedesktop.secrets` and read the item once the keyring is unlocked; we do not — and cannot, without a separate broker process with its own ACL — distinguish a request originating from `cloakd` from one originating from any other process owned by the same user. Headless / SSH sessions where no keyring agent is running fall back to `CLOAK_PEPPER_FILE` (file mode 0600 enforced).
- **Operational compromise of the publishing pipeline.** Releases are signed by `release.yml` running with the GitHub Actions OIDC identity; a compromise of that workflow's signing identity would let an attacker mint a "valid" release. The verification step (`docs/RELEASE.md`) binds the signature to a specific workflow path at a specific tag, so substituting an alternative signer would fail `cosign verify-blob`.
- **Side-channels: cache timing, EM, power.** Argon2id has timing-safety guarantees; everything else is best-effort.

## Trust assumptions

1. The host OS kernel correctly enforces UID isolation and reports peer credentials honestly (SCM_CREDENTIALS, audit_token_t).
2. The macOS Keychain correctly enforces its ACL; an unsigned binary cannot read the pepper item that's ACL-restricted to `cloakd`.
3. libsodium's primitives are correct (XChaCha20-Poly1305-IETF, Argon2id, randombytes_buf).
4. SQLite WAL + fsync gives durable, atomic single-file writes.
5. The user's passphrase entropy + the pepper jointly resist offline cracking; the pepper alone makes the file useless to a thief who lacks the keychain item.

## Residual risks accepted for v1.0

- No certificate pinning on outbound HTTP.
- No swap-disable / mlock on `cloakd`.
- No Apple notarization on macOS / no SignPath OV signing on Windows. Cosign keyless + SLSA L3 provenance is shipped instead.
- No fuzz-tested IPC parser (1M-iteration target deferred).
- No formal verification of the audit hash chain.
- Linux Secret Service has no per-process ACL — see "What Cloak does not defend against" above.
- Windows support is deferred to v1.0.1; do not run v1.0 on Windows in production.

Session tokens use constant-time comparison
(`subtle::ConstantTimeEq::ct_eq` in `crates/cloak-core/src/session.rs:124`)
— this was a v0.1 residual risk and is no longer one.
