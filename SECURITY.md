# Security policy

## Reporting a vulnerability

Email **security@cloak.dev** (PGP key TBD) or use GitHub Private Vulnerability Reporting.

We aim to:
- Acknowledge within **72 hours**.
- Provide a status update within **7 days**.
- Ship a fix or mitigation within **90 days** of the report.

If we cannot meet these timelines we will tell you in writing and explain why.

## In scope
- Cryptographic flaws in vault construction, KDF, AEAD usage.
- Peer-authentication bypasses (impersonation, PID recycle, code-sig spoofing).
- Plaintext secret material reaching the model surface (any MCP tool returning a raw key).
- Audit log tampering not detected by `cloak audit verify`.
- Privilege escalation between peers (CLI vs. MCP shim).

## Out of scope (v1.0)
- Issues that require root on the user's machine.
- Issues that depend on the user pasting a secret value into a chat.
- Macros / shell aliases that wrap `cloak show`.
- Side channels (cache timing, EM, power) — best-effort only.
- Windows: deferred to v1.0.1 ([issue #3](https://github.com/cloakward/cloak/issues/3)). Issues against the Windows code paths in v1.0 are not in-scope.

## Safe harbor
We follow the [disclose.io](https://disclose.io) safe-harbor model. Good-faith research, clearly within scope, will not be pursued legally.

## Past advisories
None yet. This file will list resolved advisories with CVE IDs once any are issued.
