# Cloak Threat Model (v1.0.6)

> This document describes what Cloak defends against, what it does not,
> and the trust assumptions underpinning each defense. It enumerates the
> primary attacker capabilities; an exhaustive defense-strength matrix
> with 15+ enumerated capabilities remains a v1.x deliverable.

## Plain English Summary

- Cloak is built for a single-user laptop or workstation with a real OS
  keychain and kernel-enforced peer credentials.
- It keeps raw stored secret values out of model-visible MCP tool output.
- It does not prevent every credential-like value from reaching the model:
  scoped minted tokens and proxied upstream responses can be returned by
  design.
- It defends against prompt injection asking for stored secrets, vault-file
  theft where the thief lacks both the local pepper and the recovery seed,
  rollback/tamper attempts, and untrusted local binaries connecting to
  `cloakd`.
- It does not defend against root/kernel compromise, a malicious same-user app
  that can read process memory or keychain-accessible items, or a user who
  deliberately pipes secrets elsewhere.
- Containers are supported for the daemon image, but they have a weaker threat
  model than the laptop install path.
- Cloak has not had a third-party security audit.

## Assets, by sensitivity

| Tier | Asset | Where it lives |
|---|---|---|
| P0 | Vault master key | Memory of `cloakd` only. Wrapped at rest. |
| P0 | Long-lived secrets (API keys, OAuth tokens, DB URLs, SSH keys) | SQLite vault, AEAD-sealed per record. Plaintext only inside `cloakd` memory during a single operation. |
| P1 | Pepper | macOS Keychain generic-password item. On Linux: freedesktop Secret Service (GNOME Keyring / KWallet) via D-Bus (W7). `CLOAK_PEPPER_FILE` 0600 escape hatch for headless environments. Cloak does not install a custom per-process or code-signature ACL for the pepper in v1.0. |
| P2 | Audit log | Hash-chained JSONL. Tamper-evident; never contains secret values. |
| P2 | Policy file | Platform config directory: `~/Library/Application Support/cloak/policy.toml` on macOS, `~/.config/cloak/policy.toml` on Linux. World-readable is acceptable. |
| P3 | Session tokens | In-memory only. Invalidated on peer exit. |

## Adversaries we defend against

| Adversary | Capability | Mitigation in v1.0 |
|---|---|---|
| **A1 — Compromised LLM / prompt injection** | Issues arbitrary tool calls; reads any output the model receives | (a) MCP surface has no raw stored-secret reveal tool. (b) `proxy_http` enforces `allowed_hosts` *and* an egress SSRF backstop that refuses any non-global destination IP (loopback/private/link-local/metadata `169.254.169.254`/ULA), validated at the resolver reqwest connects through, so DNS-rebinding on an allowlisted name cannot reach internal services. (c) Audit log records every privileged call. (d) `mint_short_lived_token` returns a derived credential, not the parent secret, but that derived credential is still visible to the model until it expires. |
| **A2 — Untrusted local process (same UID)** | Connects to the daemon socket, reads files in `~/Library` | Same-UID requirement (kernel-level peer-cred check) + installed-binary identity: production `cloakd` pins trusted peers to SHA-256 hashes of the `cloak` and `cloak-mcp` binaries installed next to the daemon at daemon startup, rejects `cloakd` as a client peer, and on macOS also verifies the running process CodeDirectory hash reported by `csops(CS_OPS_CDHASH)`. Handshake role is bound to peer kind (`cli.handshake` only from `cloak`, `mcp.handshake` only from `cloak-mcp`). This rejects arbitrary renamed binaries and post-start binary/path swaps, but assumes the install directory was not already attacker-modified before `cloakd` started. Use Homebrew, verified release tarballs, or an admin-managed install path for production. |
| **A3 — Vault-file thief (different UID, file-only access)** | Steals `vault.cloak` from a backup or shared filesystem | (a) Normal unlock requires both the passphrase and a pepper from the OS keychain: the passphrase is HMAC'd with the pepper *before* KDF. Without the pepper, brute-force of the passphrase wrap is infeasible even with weak passphrases. (b) Recovery unlock requires the 24-word recovery seed instead; storing the seed next to the vault backup defeats this protection. (c) AEAD tag on every record + master-key wrap. |
| **A4 — Network attacker (TLS)** | MITM on the daemon's outbound HTTP | (a) reqwest + rustls + system root store; no http://; no redirects to disallowed hosts. (b) Certificate pinning is **not** in v1.0 and is documented as a residual risk. |
| **A5 — Memory dump of `cloakd`** | Postmortem core, swap, hibernate | (a) `Secret<T>` zeroize-on-drop on every secret-typed value. (b) Master key kept only while the daemon vault is unlocked; stopping the daemon (`cloak daemon stop` or `cloak panic`) drops that in-memory state. (c) Swap-disable is **not** done in v1.0; users on shared servers should disable swap or use full-disk encryption. |
| **A6 — Tamper with vault file at rest** | Flip bytes in salt, ciphertext, header | AEAD tag detects any byte flip; typed `Error::Aead` (no panic). |
| **A7 — Rollback to earlier vault state** | Restore an older `vault.cloak` to undo a rotation | Monotonic counter committed to the vault's `meta` table; every write enforces strict increase via `bump_counter`. Cloak also mirrors the counter plus a SHA-256 commitment to the logical vault state into a second OS-keychain item (`dev.cloak` / `vault.rollback-counter.v1`) on every successful vault write. On `Vault::open` the file state is compared to the keychain mirror: file state == mirror is silent, any mismatch after a mirror exists is rejected as `Error::VaultRollbackDetected` *before* any record is decrypted. A missing mirror is seeded from the vault file on first open. Pre-1.0.2 counter-only mirrors require explicit operator adoption with `cloak rollback adopt-state --yes`; they are not silently trusted because they cannot prove pre-upgrade history. Read-side rollback is therefore detected on every open, not just on the next write, and an old snapshot cannot be accepted merely by editing its plaintext counter after the state mirror exists. The OS keychain provides a real out-of-band store; in the `CLOAK_PEPPER_FILE` fallback the mirror is written next to the pepper file (mode 0600) and an attacker who can roll back the vault file can also roll back the counter file in lockstep — see "Residual risks" below. |
| **A8 — PID recycle attack** | Reuse a freed PID to impersonate a trusted peer | macOS: at handshake `cloakd` calls `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)` to capture the peer's 32-byte `audit_token_t` (which carries the kernel's non-recycling pidversion in `val[7]`) and stores it in the `SessionRecord`; every subsequent request constant-time-compares the stored bytes via `subtle::ConstantTimeEq`. In parallel, a per-connection `kqueue` watcher armed with `EVFILT_PROC | NOTE_EXIT` revokes every session bound to the connection when the peer exits. Linux requires race-free `SO_PEERPIDFD`; `pidfd_open(SO_PEERCRED.pid)` is not used for socket-peer identity because it can race PID reuse. If `SO_PEERPIDFD` is unavailable, `cloakd` refuses to issue a session token. |
| **A9 — Same-UID attacker bypassing the CLI** | Connect to the `cloakd` UDS directly (skipping `cloak`) and request `vault.show` while supplying any "user already approved" flag in the payload | `cloakd` fires the Touch ID (macOS) / polkit (Linux) prompt itself in its `vault.show` handler before any plaintext leaves the vault; the daemon does **not** trust any client-supplied biometric assertion, including the legacy `skip_biometric` field. On cancel / failure / unavailable the daemon returns `biometric-failed`. Source: `crates/cloak-core/src/biometric.rs`, dispatch in `crates/cloak-core/src/daemon.rs::vault.show`. |

## What Cloak **does not** defend against (honest list)

- **Root / kernel-level local attacker.** Any process with root on the user's machine can read `cloakd`'s memory or substitute its binary. This is out of scope.
- **Compromised libsodium source/build.** We trust the upstream libsodium source archive pinned in `scripts/prepare-libsodium-dist.sh` and the local C/Rust toolchain that builds it.
- **Macros / shell aliases that wrap `cloak show`.** A user who pipes `cloak show` to a clipboard manager or a script that exfiltrates is opting into that risk.
- **Same-UID erasure of tamper-evidence state.** A same-UID attacker can delete both the audit log and its external keychain anchor, or both the vault and the rollback mirror. In-place tampering (truncation, edits, reorder, counter-bump on a stale snapshot) is always detected and fails closed; *full* erasure of an **established** profile now also fails closed (the daemon refuses to silently re-genesis and requires an explicit `cloak audit adopt-head --yes` / `cloak rollback adopt-state --yes` after review). Cloak cannot prevent the same-UID attacker from deleting the underlying data itself — only from doing so silently.
- **The model's *output* containing secret material the user pastes back in.** If the user pastes a secret into a Claude prompt, Cloak cannot help. Cloak's value is making that paste unnecessary.
- **Remote APIs echoing sensitive data.** `proxy_http` redacts exact representations of the attached secret from upstream response headers/body and marks the response as redacted, but the upstream response still goes to the MCP client. Cloak cannot prove a remote API will not echo transformed credentials, submitted bodies, or unrelated sensitive data.
- **macOS Gatekeeper notarization.** Production macOS release tags are hard-gated on Developer ID signing and Apple notarization in `release.yml`; prerelease/fork preview builds may be unsigned and can require `xattr -d com.apple.quarantine`. Bare Mach-O command-line tools cannot be stapled in-place, so Gatekeeper may fetch the notary ticket online on first launch. Cosign keyless + SLSA L3 provenance remain the canonical "did CI build these exact bytes" check (`docs/RELEASE.md`).
- **Cross-platform parity.** Stable release artifacts currently target macOS + Linux. Windows is not part of the current release artifacts yet ([issue #2](https://github.com/cloakward/cloak/issues/2)). On Linux the keychain pepper uses freedesktop Secret Service and the user-presence gate is enforced via polkit (`dev.cloak.show-secret`, default policy `auth_self`); when no polkit agent is registered, `cloak show` fails closed unless the user passes `--no-biometric`.
- **Linux desktop pepper via Secret Service.** On Linux, Cloak stores the pepper as a libsecret item in the user's default (or `login`) collection. A malicious local app running as the same UID can call `org.freedesktop.secrets` and read the item once the keyring is unlocked; we do not — and cannot, without a separate broker process with its own ACL — distinguish a request originating from `cloakd` from one originating from any other process owned by the same user. Headless / SSH sessions where no keyring agent is running fall back to `CLOAK_PEPPER_FILE` (file mode 0600 enforced).
- **macOS pepper is not a code-signature ACL boundary.** Cloak stores the pepper as a Security Framework generic-password item and does not create a custom `SecAccess` / code-signature ACL for `cloakd` in v1.0. Treat the pepper as protection against vault-file-only theft, not as a complete defense against a malicious same-user desktop process that can satisfy macOS Keychain access policy.
- **Operational compromise of the publishing pipeline.** Releases are signed by `release.yml` running with the GitHub Actions OIDC identity; a compromise of that workflow's signing identity would let an attacker mint a "valid" release. The verification step (`docs/RELEASE.md`) binds the signature to a specific workflow path at a specific tag, so substituting an alternative signer would fail `cosign verify-blob`.
- **Pre-start replacement in mutable user-owned install directories.** Binary hash pinning is a startup trust-on-first-use check over the installed `cloak` and `cloak-mcp` siblings. If a same-UID attacker can replace those files before `cloakd` starts, the daemon cannot distinguish that from the user's intended local build. Protect production install directories and verify release signatures before first start.
- **Side-channels: cache timing, EM, power.** Argon2id has timing-safety guarantees; everything else is best-effort.

## Container deployment (`ghcr.io/cloakward/cloakd`)

Cloak's primary threat model is a **single-user laptop** with a real OS keychain (macOS Keychain or freedesktop Secret Service) and kernel-enforced peer-credential isolation. The container image (`ghcr.io/cloakward/cloakd:VERSION`) ships the same daemon binary, but the surrounding security posture is materially different. Operators running `cloakd` in a container should read this section before adopting it for anything other than personal homelab use.

### What still holds

- **No raw stored-secret reveal over the wire to the model.** The same six-tool MCP surface; the same user-presence-gated `vault.show` path (which is CLI-only — `vault.show` is *not* one of the six MCP tools and is never reachable from the model); the same `Secret<T>` zeroize-on-drop discipline. Derived tokens and proxied upstream responses remain visible to the MCP client as described above.
- **Vault file confidentiality at rest.** AEAD per record + master-key wrap + Argon2id KDF are all unchanged. A stolen `vault.cloak` file is still useless to anyone who lacks both the pepper for passphrase unlock and the 24-word recovery seed for recovery unlock.
- **Audit log integrity.** Hash-chained JSONL works the same in a container; mount it on a persistent volume and `cloak audit verify` (CLI on the host) detects tampering.
- **Container provenance is separate from tarball provenance.** Supported release Docker channels are built by `docker-push.yml` after a GitHub Release is published. `docker/build-push-action` attaches BuildKit provenance/SBOM metadata, and the workflow cosign-signs the immutable multi-arch manifest digest before promoting public stable tags. This is separate from the tarball SLSA envelope generated by `release.yml`.

### What changes in a container

- **No OS keychain.** macOS Keychain doesn't exist inside a Linux container; freedesktop Secret Service requires a running session keyring, which a typical headless container does not have. The pepper falls back to `CLOAK_PEPPER_FILE`. Operators MUST mount the pepper as a Docker secret at `/run/secrets/cloak-pepper` (mode 0o600). The daemon reads `CLOAK_PEPPER_FILE` and refuses to load any pepper file readable by group or world. Anything else (`tmpfs`, `bind mount` from a world-readable host path, `--env CLOAK_PEPPER=...`) downgrades the threat model and is documented as a residual risk for that operator.
- **Peer-credential semantics shift to namespace UIDs.** The daemon's `SO_PEERCRED` path reads PIDs and UIDs in the daemon's PID and user namespaces. A peer in another container or in the host's namespace presents UIDs that may collide with the daemon's notion of "trusted same-UID". The installed-binary hash allowlist still applies, but the `getpeereid` UID equality check assumes a shared UID namespace — which is the default for `--ipc=host` and bind-mounted UDS sockets, but NOT for sandboxed peer containers. Operators running multi-container setups MUST audit which containers can `connect()` the cloakd UDS.
- **Linux pidfd watcher behavior depends on the host kernel.** The PID-recycle defense requires `SO_PEERPIDFD` (Linux 6.5+) and a runtime/seccomp profile that permits it. Hardened container runtimes may block pidfd socket options; Cloak fails closed in that case by refusing to issue a session token to that peer.
- **No interactive user-presence prompt inside the container.** Containers have no Touch ID, no polkit, no LocalAuthentication. The published image starts `cloakd` by default and includes a trusted `cloak` CLI sibling only so installed-binary peer pinning can succeed; it is not a drop-in MCP sidecar image because it does not ship `cloak-mcp`. Run `cloak show` from the host CLI when you need an interactive reveal. Daemon-side `vault.show` still fails closed when no user-presence provider is available.
- **Read-side rollback detection in containers depends on the keychain mirror, which the container does not have.** With `CLOAK_PEPPER_FILE` set the mirror is written to a sibling file (mode 0600) inside the vault directory — an attacker who can roll back `vault.cloak` from a host volume snapshot can also roll back `rollback-counter` in lockstep, defeating the detection. Mount your vault directory on a persistent host volume that you back up; if you can give the daemon access to a real out-of-band keychain (sidecar to a host-keyring proxy, hardware token, KMS-wrapped envelope), you regain the laptop-grade rollback guarantees.
- **Verify the signed image digest.** Always pin by digest in production and verify the cosign signature on the immutable manifest digest:
  ```
  cosign verify \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity "https://github.com/cloakward/cloak/.github/workflows/docker-push.yml@refs/tags/<TAG>" \
    ghcr.io/cloakward/cloakd@sha256:...
  ```

### Recommended container deployment

- Single user, single host, single daemon container. Multi-tenant cloakd is not in the v1.0 threat model.
- Pepper mounted via Docker secret (`/run/secrets/cloak-pepper`, mode 0o600).
- Vault on a named volume mounted at `/var/lib/cloak`, backed by host-level encryption (LUKS, FileVault, BitLocker on the host, etc.) — Cloak's at-rest crypto is good but defense-in-depth helps. The image sets `HOME=/var/lib/cloak`, `XDG_DATA_HOME=/var/lib/cloak/.local/share`, `XDG_CONFIG_HOME=/var/lib/cloak/.config`, and `XDG_RUNTIME_DIR=/var/lib/cloak/run`, so the default vault, audit log, policy file, and socket all land under that volume. Bind mounts must be writable by distroless `nonroot` (`65532:65532`).
- Treat the published image as daemon/CLI-only. Production MCP peer auth requires the exact `cloak-mcp` executable to be visible to `cloakd` at startup as a trusted sibling or via `CLOAK_MCP_BIN`; a `cloak-mcp` in a separate container normally will not satisfy the daemon's `/proc/<pid>/exe` hash check and will fail closed. For production MCP, use the host release install, or mount the exact read-only `cloak-mcp` binary into the daemon container at the same path visible to the running process before `cloakd` starts.
- UDS (`/var/lib/cloak/run/cloakd.sock` by default in the image) should only be bind-mounted into peers that satisfy the trusted binary rule above; do NOT expose it via `--ipc=host` to untrusted containers.
- Run as `nonroot` (the distroless `cc-debian12:nonroot` base does this by default; do not override).
- Treat the container as having **same threat model as a laptop daemon running as a single user**, not as a multi-tenant service. If you need multi-tenant, that's a v1.x design problem (remote auth, per-tenant master keys, etc.) and is not yet defined.

### Out of scope for container deployments

- Network-exposed cloakd (TCP listener with TLS + remote auth). v1.x.
- Per-tenant key isolation. v1.x.
- Automated end-to-end MCP sidecar container examples with trusted `cloak-mcp` binary mounting. v1.x.
- Confidential-computing / TEE attestation. Not on the roadmap.

## Trust assumptions

1. The host OS kernel correctly enforces UID isolation and reports peer credentials honestly (SCM_CREDENTIALS, audit_token_t).
2. The OS keychain / Secret Service protects the pepper from vault-file-only attackers and returns existing items or typed errors correctly. It is not a custom per-process ACL boundary in v1.0.
3. libsodium's primitives are correct (XChaCha20-Poly1305-IETF, Argon2id, randombytes_buf).
4. SQLite WAL + fsync gives durable, atomic single-file writes.
5. The user's passphrase entropy + the pepper jointly resist offline cracking of the normal wrap. The recovery seed is an independent unlock path; storing it with the vault file defeats the vault-file-theft protection.

## BIP-39 recovery seed

At vault creation Cloak generates a fresh 256-bit entropy, encodes it as a
24-word English BIP-39 mnemonic, and derives a 32-byte recovery key from
the standard BIP-39 seed (`PBKDF2-HMAC-SHA512`, 2048 iterations, salt
`"mnemonic"`, empty BIP-39 passphrase — first 32 bytes). The master key is
wrapped twice and stored side-by-side in the `meta` row:

- `wrap_aead` — under `wrap_key = Argon2id(passphrase, pepper)` with AAD
  `cloak.master.v1`. Used by `cloak unlock`.
- `recovery_wrap_aead` — under the recovery key with AAD
  `cloak.recovery.v1`. Used by `cloak restore`.

The mnemonic itself is shown to the user once at vault creation and never
persisted; Cloak does not retain a copy. `cloak restore` re-derives the
master key from the seed and re-wraps it under a fresh passphrase,
leaving the recovery wrap intact so the same words keep working. `cloak
backup verify` confirms a candidate seed round-trips the recovery wrap
without performing a restore.

**Threat implications.** A vault-file thief now has two possible offline
targets: the normal passphrase wrap, which still requires the local pepper,
or the recovery wrap, which requires the 24-word seed. Users who write the
seed down on paper and store it offline keep the `A3` posture: file-only
access still lacks both unlock inputs. Users who store the seed alongside the
vault file in the same backup degrade `A3`: if the backup leaks, so does
access. The recovery seed is documented as "treat like the passphrase"
wherever it is mentioned in user-facing output.

The recovery path is **CLI-only** — there is no IPC method or MCP tool
that can read or use the recovery wrap. The same-UID `A2` attacker who
can talk to the daemon socket does not gain a new privilege from this
feature.

## Residual risks accepted for v1.0.6

- No certificate pinning on outbound HTTP.
- No swap-disable / mlock on `cloakd`.
- Production macOS release tags are Developer ID signed and submitted to Apple notarization; prerelease/fork previews may be unsigned. SignPath OV signing on Windows is still deferred. Cosign keyless + SLSA L3 provenance cover tarballs and `.dxt` packages built by the current release workflow.
- No fuzz-tested IPC parser (1M-iteration target deferred).
- No formal verification of the audit hash chain.
- Linux Secret Service has no per-process ACL — see "What Cloak does not defend against" above.
- Windows support is deferred; do not run Cloak on Windows in production yet.
- Cloak mirrors the vault counter and state digest into the OS keychain; read-side rollback is now detected on every `Vault::open`. With `CLOAK_PEPPER_FILE` set the mirror is written to a 0600 sibling file (`<vault_dir>/rollback-counter`) instead of the keychain — an attacker who can roll back `vault.cloak` can also roll back the counter file in lockstep, defeating the detection. The OS keychain path provides the real out-of-band guarantee; the file fallback is for environments where the keychain isn't available, with documented weaker guarantees.

Session tokens use constant-time comparison
(`subtle::ConstantTimeEq::ct_eq` in `crates/cloak-core/src/session.rs:124`)
— this was a v0.1 residual risk and is no longer one.
