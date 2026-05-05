# Cloak Threat Model (v0.1)

> This is the v0.1 threat model. It documents what Cloak defends against, what
> it does not, and the trust assumptions underpinning each defense. The
> 8-week plan called for an exhaustive THREAT_MODEL.md with 15+ enumerated
> attacker capabilities and a defense-strength matrix; the v0.1 drop covers
> the primary axes and explicitly defers the rest to v1.x.

## Assets, by sensitivity

| Tier | Asset | Where it lives |
|---|---|---|
| P0 | Vault master key | Memory of `cloakd` only. Wrapped at rest. |
| P0 | Long-lived secrets (API keys, OAuth tokens, DB URLs, SSH keys) | SQLite vault, AEAD-sealed per record. Plaintext only inside `cloakd` memory during a single operation. |
| P1 | Pepper | macOS Keychain (system-keychain item, ACL-restricted to `cloakd` codesig). |
| P1 | Recovery seed | Shown once at `init`; never persisted by `cloakd`. |
| P2 | Audit log | Hash-chained JSONL. Tamper-evident; never contains secret values. |
| P2 | Policy file | `~/.config/cloak/policy.toml`. World-readable is acceptable. |
| P3 | Session tokens | In-memory only. Invalidated on peer exit. |

## Adversaries we defend against

| Adversary | Capability | Mitigation in v0.1 |
|---|---|---|
| **A1 — Compromised LLM / prompt injection** | Issues arbitrary tool calls; reads any output the model receives | (a) MCP surface has no plaintext-reveal tool. (b) `proxy_http` enforces `allowed_hosts`. (c) Audit log records every privileged call. (d) `mint_short_lived_token` returns a derivative, not the parent. |
| **A2 — Untrusted local process (same UID)** | Connects to the daemon socket, reads files in `~/Library` | (a) Socket mode 0600 + UID check. (b) Peer-credential auth: PID + code-signature must match an allowlisted binary. (c) Vault file is AEAD-sealed even if read. |
| **A3 — Vault-file thief (different UID, file-only access)** | Steals `vault.cloak` from a backup or shared filesystem | (a) Argon2id keyed mode: passphrase is HMAC'd with a pepper from the OS keychain *before* KDF. Without the pepper, brute-force is infeasible even with weak passphrases. (b) AEAD tag on every record + master-key wrap. |
| **A4 — Network attacker (TLS)** | MITM on the daemon's outbound HTTP | (a) reqwest + rustls + system root store; no http://; no redirects to disallowed hosts. (b) Certificate pinning is **not** in v0.1 and is documented as a residual risk. |
| **A5 — Memory dump of `cloakd`** | Postmortem core, swap, hibernate | (a) `Secret<T>` zeroize-on-drop on every secret-typed value. (b) Master key kept only when unlocked; `cloak lock` zeroizes. (c) Swap-disable is **not** done in v0.1; users on shared servers should disable swap or use full-disk encryption. |
| **A6 — Tamper with vault file at rest** | Flip bytes in salt, ciphertext, header | AEAD tag detects any byte flip; typed `Error::Aead` (no panic). |
| **A7 — Rollback to earlier vault state** | Restore an older `vault.cloak` to undo a rotation | Monotonic counter committed to the macOS Keychain (separate item). On unlock, the counter must be ≥ the stored value, else `Error::VaultRollbackDetected`. |
| **A8 — PID recycle attack** | Reuse a freed PID to impersonate a trusted peer | The session token is bound to the connection's audit-token on macOS; if the connection's peer process exits, the kqueue `EVFILT_PROC` watcher invalidates the token before a new PID can recycle in. |

## What Cloak **does not** defend against (honest list)

- **Root / kernel-level local attacker.** Any process with root on the user's machine can read `cloakd`'s memory or substitute its binary. This is out of scope.
- **Compromised libsodium build.** We trust the upstream libsodium static binary we link.
- **Macros / shell aliases that wrap `cloak show`.** A user who pipes `cloak show` to a clipboard manager or a script that exfiltrates is opting into that risk.
- **The model's *output* containing secret material the user pastes back in.** If the user pastes a secret into a Claude prompt, Cloak cannot help. Cloak's value is making that paste unnecessary.
- **macOS Gatekeeper notarization.** v0.1 binaries are not notarized. Users must run `xattr -d com.apple.quarantine`. v1.0 will notarize.
- **Cross-platform parity.** v0.1 is macOS-only. Linux and Windows builds compile but biometric, peer auth, and keychain pepper are stubs.
- **Operational compromise of the publishing pipeline.** v0.1 builds are dev builds; SLSA L3 provenance + cosign signatures are deferred to v1.0.
- **Side-channels: cache timing, EM, power.** Argon2id has timing-safety guarantees; everything else is best-effort.

## Trust assumptions

1. The host OS kernel correctly enforces UID isolation and reports peer credentials honestly (SCM_CREDENTIALS, audit_token_t).
2. The macOS Keychain correctly enforces its ACL; an unsigned binary cannot read the pepper item that's ACL-restricted to `cloakd`.
3. libsodium's primitives are correct (XChaCha20-Poly1305-IETF, Argon2id, randombytes_buf).
4. SQLite WAL + fsync gives durable, atomic single-file writes.
5. The user's passphrase entropy + the pepper jointly resist offline cracking; the pepper alone makes the file useless to a thief who lacks the keychain item.

## Residual risks accepted for v0.1

- No certificate pinning on outbound HTTP.
- No swap-disable / mlock on `cloakd`.
- No notarization on macOS / SignPath on Windows.
- No fuzz-tested IPC parser (1M-iteration target deferred).
- No formal verification of the audit hash chain.
- No constant-time comparison of session tokens (`subtle::ConstantTimeEq` will be used; verify in code review).
