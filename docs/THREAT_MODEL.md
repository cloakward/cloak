# Cloak Threat Model (v0.9.0-rc2)

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
| P2 | Audit log | Hash-chained JSONL. Tamper-evident; never contains secret values. |
| P2 | Policy file | `~/.config/cloak/policy.toml`. World-readable is acceptable. |
| P3 | Session tokens | In-memory only. Invalidated on peer exit. |

## Adversaries we defend against

| Adversary | Capability | Mitigation in v1.0 |
|---|---|---|
| **A1 — Compromised LLM / prompt injection** | Issues arbitrary tool calls; reads any output the model receives | (a) MCP surface has no plaintext-reveal tool. (b) `proxy_http` enforces `allowed_hosts`. (c) Audit log records every privileged call. (d) `mint_short_lived_token` returns a derivative, not the parent. |
| **A2 — Untrusted local process (same UID)** | Connects to the daemon socket, reads files in `~/Library` | Same-UID requirement (kernel-level peer-cred check) + on-disk basename allowlist (`cloak`, `cloak-mcp`, `cloakd`). The peer's binary SHA-256 is recorded in the audit log but is not yet an enforcement gate — true mach-o code-directory matching is a v1.0.1 deliverable. A same-UID attacker who renames their binary `cloak` will pass this gate; the macOS Keychain ACL on the pepper item, the `vault.unlock` passphrase requirement, and the policy engine's allowed-hosts gate are the real defenses against arbitrary-binary attacks at the same UID. |
| **A3 — Vault-file thief (different UID, file-only access)** | Steals `vault.cloak` from a backup or shared filesystem | (a) Argon2id keyed mode: passphrase is HMAC'd with a pepper from the OS keychain *before* KDF. Without the pepper, brute-force is infeasible even with weak passphrases. (b) AEAD tag on every record + master-key wrap. |
| **A4 — Network attacker (TLS)** | MITM on the daemon's outbound HTTP | (a) reqwest + rustls + system root store; no http://; no redirects to disallowed hosts. (b) Certificate pinning is **not** in v1.0 and is documented as a residual risk. |
| **A5 — Memory dump of `cloakd`** | Postmortem core, swap, hibernate | (a) `Secret<T>` zeroize-on-drop on every secret-typed value. (b) Master key kept only when unlocked; `cloak lock` zeroizes. (c) Swap-disable is **not** done in v1.0; users on shared servers should disable swap or use full-disk encryption. |
| **A6 — Tamper with vault file at rest** | Flip bytes in salt, ciphertext, header | AEAD tag detects any byte flip; typed `Error::Aead` (no panic). |
| **A7 — Rollback to earlier vault state** | Restore an older `vault.cloak` to undo a rotation | Monotonic counter committed to the vault's `meta` table; every write enforces strict increase via `bump_counter`. v1.0 also mirrors the counter into a second OS-keychain item (`dev.cloak` / `vault.rollback-counter.v1`) on every successful vault write. On `Vault::open` the file counter is compared to the keychain mirror: file == mirror is silent, file > mirror refreshes the mirror (legitimate cross-device rsync), file < mirror is rejected as `Error::VaultRollbackDetected` *before* any record is decrypted. Read-side rollback is therefore detected on every open, not just on the next write. The OS keychain provides a real out-of-band store; in the `CLOAK_PEPPER_FILE` fallback the mirror is written next to the pepper file (mode 0600) and an attacker who can roll back the vault file can also roll back the counter file in lockstep — see "Residual risks" below. |
| **A8 — PID recycle attack** | Reuse a freed PID to impersonate a trusted peer | macOS: at handshake `cloakd` calls `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)` to capture the peer's 32-byte `audit_token_t` (which carries the kernel's non-recycling pidversion in `val[7]`) and stores it in the `SessionRecord`; every subsequent request constant-time-compares the stored bytes via `subtle::ConstantTimeEq`. In parallel, a per-connection `kqueue` watcher armed with `EVFILT_PROC | NOTE_EXIT` (wrapped in `tokio::io::unix::AsyncFd`) revokes every session bound to the connection the instant the kernel reports the peer has exited, closing the PID-recycle window before any other process can inherit the freed PID. Linux (v0.9.0-rc2, see [#21](https://github.com/cloakward/cloak/issues/21)): the kernel `pidfd` capture path (`getsockopt(SOL_SOCKET, SO_PEERPIDFD)` with `pidfd_open(SO_PEERCRED.pid)` fallback) and the per-connection `PidfdWatcher` are *implemented* in `cloak-core` but *not wired in* at the daemon's `serve_conn` call site for this release — `getsockopt(SO_PEERPIDFD)` had a reproducible interaction on the GitHub Actions runner kernel that closed the cloak-mcp peer socket before it could send its first frame, and we did not ship a workaround we trusted on every Linux kernel within the release window. Until v1.0.1, peer identity on Linux is the `SO_PEERCRED` triple plus a SHA-256 of the peer's `/proc/<pid>/exe` snapshot taken at handshake — same surface as v0.1 — and session revocation is socket-FIN-driven only. The PID-recycle window on Linux is therefore bounded by *the time between the peer task's exit and its socket FIN reaching `cloakd`* rather than by the kernel's exit notification; this is strictly weaker than the macOS kqueue path and is documented honestly here rather than papered over. |
| **A9 — Same-UID attacker bypassing the CLI** | Connect to the `cloakd` UDS directly (skipping `cloak`) and request `vault.show` while supplying any "user already approved" flag in the payload | `cloakd` fires the Touch ID (macOS) / polkit (Linux) prompt itself in its `vault.show` handler before any plaintext leaves the vault; the daemon does **not** trust any client-supplied biometric assertion. The only escape hatch is the explicit `skip_biometric: true` opt-out (forwarded from `cloak --no-biometric show NAME`) for documented headless contexts. On cancel / failure / unavailable the daemon returns `biometric-failed`. Source: `crates/cloak-core/src/biometric.rs`, dispatch in `crates/cloak-core/src/daemon.rs::vault.show`. |

## What Cloak **does not** defend against (honest list)

- **Root / kernel-level local attacker.** Any process with root on the user's machine can read `cloakd`'s memory or substitute its binary. This is out of scope.
- **Compromised libsodium build.** We trust the upstream libsodium static binary we link.
- **Macros / shell aliases that wrap `cloak show`.** A user who pipes `cloak show` to a clipboard manager or a script that exfiltrates is opting into that risk.
- **The model's *output* containing secret material the user pastes back in.** If the user pastes a secret into a Claude prompt, Cloak cannot help. Cloak's value is making that paste unnecessary.
- **macOS Gatekeeper notarization.** v1.0 macOS binaries are signed with a Developer ID Application certificate, submitted to Apple's notary service via `xcrun notarytool`, and ship with a notarization ticket — no `xattr -d com.apple.quarantine` needed on a default Gatekeeper configuration. Cosign keyless + SLSA L3 provenance still ship in parallel and remain the canonical "did CI build these exact bytes" check (`docs/RELEASE.md`).
- **Cross-platform parity.** v1.0 ships macOS + Linux. Windows is deferred to v1.0.1 ([issue #3](https://github.com/cloakward/cloak/issues/3)). On Linux the keychain pepper is real (W7 freedesktop Secret Service) and the user-presence gate is enforced via polkit (`dev.cloak.show-secret`, default policy `auth_self_keep`); when no polkit agent is registered, `cloak show` fails closed unless the user passes `--no-biometric`.
- **Linux desktop pepper via Secret Service.** v1.0 stores the pepper as a libsecret item in the user's default (or `login`) collection. A malicious local app running as the same UID can call `org.freedesktop.secrets` and read the item once the keyring is unlocked; we do not — and cannot, without a separate broker process with its own ACL — distinguish a request originating from `cloakd` from one originating from any other process owned by the same user. Headless / SSH sessions where no keyring agent is running fall back to `CLOAK_PEPPER_FILE` (file mode 0600 enforced).
- **Operational compromise of the publishing pipeline.** Releases are signed by `release.yml` running with the GitHub Actions OIDC identity; a compromise of that workflow's signing identity would let an attacker mint a "valid" release. The verification step (`docs/RELEASE.md`) binds the signature to a specific workflow path at a specific tag, so substituting an alternative signer would fail `cosign verify-blob`.
- **Side-channels: cache timing, EM, power.** Argon2id has timing-safety guarantees; everything else is best-effort.

## Container deployment (`ghcr.io/cloakward/cloakd`)

Cloak's primary threat model is a **single-user laptop** with a real OS keychain (macOS Keychain or freedesktop Secret Service) and kernel-enforced peer-credential isolation. The container image (`ghcr.io/cloakward/cloakd:VERSION`) ships the same daemon binary, but the surrounding security posture is materially different. Operators running `cloakd` in a container should read this section before adopting it for anything other than personal homelab use.

### What still holds

- **No plaintext over the wire to the model.** The same six-tool MCP surface; the same biometric-gated `vault.show` path; the same `Secret<T>` zeroize-on-drop discipline. A compromised model client cannot extract secret material from a containerized daemon any more easily than from a laptop daemon.
- **Vault file confidentiality at rest.** AEAD per record + master-key wrap + Argon2id KDF are all unchanged. A stolen `vault.cloak` file is still useless to anyone who lacks the pepper.
- **Audit log integrity.** Hash-chained JSONL works the same in a container; mount it on a persistent volume and `cloak audit verify` (CLI on the host) detects tampering.
- **Cosign + SLSA L3 attestation.** The container image is built by the same pinned-workflow `release.yml` and inherits the same provenance chain as the tarballs. `cosign verify` on the image digest works (image signing itself is a v1.0.1 follow-up, but the attestation manifest is already attached via `provenance: true` on `docker/build-push-action`).

### What changes in a container

- **No OS keychain.** macOS Keychain doesn't exist inside a Linux container; freedesktop Secret Service requires a running session keyring, which a typical headless container does not have. The pepper falls back to `CLOAK_PEPPER_FILE`. Operators MUST mount the pepper as a Docker secret at `/run/secrets/cloak-pepper` (mode 0o600). The daemon reads `CLOAK_PEPPER_FILE` and refuses to load any pepper file readable by group or world. Anything else (`tmpfs`, `bind mount` from a world-readable host path, `--env CLOAK_PEPPER=...`) downgrades the threat model and is documented as a residual risk for that operator.
- **Peer-credential semantics shift to namespace UIDs.** The daemon's `SO_PEERCRED` path reads PIDs and UIDs in the daemon's PID and user namespaces. A peer in another container or in the host's namespace presents UIDs that may collide with the daemon's notion of "trusted same-UID". The on-disk binary basename allowlist (`cloak`, `cloak-mcp`, `cloakd`) still applies, but the `getpeereid` UID equality check assumes a shared UID namespace — which is the default for `--ipc=host` and bind-mounted UDS sockets, but NOT for sandboxed peer containers. Operators running multi-container setups MUST audit which containers can `connect()` the cloakd UDS.
- **Linux pidfd watcher behavior depends on the host kernel.** The PID-recycle defense (`SO_PEERPIDFD` + `pidfd_open` + `tokio::io::unix::AsyncFd` watcher) requires kernel ≥ 5.3 AND that pidfd be enabled in the container's seccomp profile. Hardened container runtimes (e.g., gVisor, Kata) may block `pidfd_open`; Cloak falls back to socket-FIN-driven session revocation in that case. The PID-recycle window then degrades to "the time between peer task exit and its socket FIN reaching cloakd" rather than the kernel's exit notification — strictly weaker than the macOS kqueue path.
- **No biometric / user-presence gate.** Containers have no Touch ID, no polkit, no LocalAuthentication. `cloak show` from inside the container will always need `--no-biometric` (and audit-log every such call). The `cloak` CLI is intended for the host, not the container; the container ships only `cloakd`.
- **Read-side rollback detection in containers depends on the keychain mirror, which the container does not have.** With `CLOAK_PEPPER_FILE` set the mirror is written to a sibling file (mode 0600) inside the vault directory — an attacker who can roll back `vault.cloak` from a host volume snapshot can also roll back `rollback-counter` in lockstep, defeating the detection. Mount your vault directory on a persistent host volume that you back up; if you can give the daemon access to a real out-of-band keychain (sidecar to a host-keyring proxy, hardware token, KMS-wrapped envelope), you regain the laptop-grade rollback guarantees.
- **Image signature verification is the consumer's responsibility.** Always pin by digest in production:
  ```
  docker pull ghcr.io/cloakward/cloakd@sha256:...
  cosign verify --certificate-identity-regexp '^https://github.com/cloakward/cloak/.github/workflows/release.yml@refs/tags/vX.Y.Z$' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    ghcr.io/cloakward/cloakd@sha256:...
  ```

### Recommended container deployment

- Single user, single host, single daemon container. Multi-tenant cloakd is not in the v1.0 threat model.
- Pepper mounted via Docker secret (`/run/secrets/cloak-pepper`, mode 0o600).
- Vault on a named volume backed by host-level encryption (LUKS, FileVault, BitLocker on the host, etc.) — Cloak's at-rest crypto is good but defense-in-depth helps.
- UDS (`/run/cloakd/cloakd.sock`) bind-mounted into peer containers that need to talk to it; do NOT expose it via `--ipc=host` to untrusted containers.
- Run as `nonroot` (the distroless `cc-debian12:nonroot` base does this by default; do not override).
- Treat the container as having **same threat model as a laptop daemon running as a single user**, not as a multi-tenant service. If you need multi-tenant, that's a v1.x design problem (remote auth, per-tenant master keys, etc.) and is not yet defined.

### Out of scope for v0.9.x containers

- Network-exposed cloakd (TCP listener with TLS + remote auth). v1.x.
- Per-tenant key isolation. v1.x.
- Image notarization equivalent (e.g. attached cosign signature on the manifest digest). v1.0.1.
- Confidential-computing / TEE attestation. Not on the roadmap.

## Trust assumptions

1. The host OS kernel correctly enforces UID isolation and reports peer credentials honestly (SCM_CREDENTIALS, audit_token_t).
2. The macOS Keychain correctly enforces its ACL; an unsigned binary cannot read the pepper item that's ACL-restricted to `cloakd`.
3. libsodium's primitives are correct (XChaCha20-Poly1305-IETF, Argon2id, randombytes_buf).
4. SQLite WAL + fsync gives durable, atomic single-file writes.
5. The user's passphrase entropy + the pepper jointly resist offline cracking; the pepper alone makes the file useless to a thief who lacks the keychain item.

## Residual risks accepted for v0.9.0-rc2

- No certificate pinning on outbound HTTP.
- No swap-disable / mlock on `cloakd`.
- macOS binaries are now Apple-notarized (Developer ID Application + `notarytool`); SignPath OV signing on Windows is still deferred (Windows itself ships in v1.0.1). Cosign keyless + SLSA L3 provenance ship for every platform regardless.
- No fuzz-tested IPC parser (1M-iteration target deferred).
- No formal verification of the audit hash chain.
- Linux Secret Service has no per-process ACL — see "What Cloak does not defend against" above.
- Windows support is deferred to v1.0.1; do not run v0.9.0-rc2 on Windows in production.
- v1.0 mirrors the counter into the OS keychain; read-side rollback is now detected on every `Vault::open`. With `CLOAK_PEPPER_FILE` set the mirror is written to a 0600 sibling file (`<vault_dir>/rollback-counter`) instead of the keychain — an attacker who can roll back `vault.cloak` can also roll back the counter file in lockstep, defeating the detection. The OS keychain path provides the real out-of-band guarantee; the file fallback is for environments where the keychain isn't available, with documented weaker guarantees.

Session tokens use constant-time comparison
(`subtle::ConstantTimeEq::ct_eq` in `crates/cloak-core/src/session.rs:124`)
— this was a v0.1 residual risk and is no longer one.
