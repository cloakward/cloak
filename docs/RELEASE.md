# Cloak release process and verification

> Audience: maintainers cutting a release, and downstream users verifying
> one. This is the source of truth for what the current release workflow
> verifies and what remains unsupported or pre-production.

## Cutting a release (maintainer steps)

1. **Land all the workstreams that should ship.** `beta` is the integration
   branch; releases are tagged off `beta` once CI is green.
2. **Bump the version.** Update `Cargo.toml::workspace.package.version` and
   `packages/cloak-mcp/package.json::version` to the new `X.Y.Z`. Update
   `CHANGELOG.md`: rename the `Unreleased` heading to `[X.Y.Z] — YYYY-MM-DD`
   and start a fresh `Unreleased` section.
3. **Tag.** `git tag -s vX.Y.Z -m "Cloak X.Y.Z"`, `git push origin vX.Y.Z`.
   The tag must be signed, annotated, and point at a commit reachable from
   `beta` or `main`; `release.yml` rejects unsigned tags, lightweight tags,
   and arbitrary commits.
4. **Watch `release.yml`.** The workflow:
   - Runs the same `ci.yml`, `security.yml`, and `smoke.yml` gates from
     the tagged commit before any release artifact is cosign-signed.
   - Builds the release artifacts in a 5-row matrix:
     macOS arm64 (`macos-26`),
     macOS x86_64 (`macos-26-intel`),
     Linux glibc x86_64 (`x86_64-unknown-linux-gnu`),
     Linux musl x86_64 (`x86_64-unknown-linux-musl`),
     Linux glibc arm64 (`aarch64-unknown-linux-gnu`).
     Windows is not part of the current release artifacts — see
     [issue #2](https://github.com/cloakward/cloak/issues/2).
   - Tarballs each row as `cloak-X.Y.Z-<target>.tar.gz`.
   - Builds Claude Desktop `.dxt` packages for macOS arm64/x64. Linux tarballs
     can still include `cloak-mcp`, but Claude Desktop's MCPB/DXT install
     surface is macOS/Windows-only and Windows is not shipped yet.
   - Aggregates `sha256sums.txt` across tarballs and `.dxt` packages.
   - Cosign-keyless-signs every tarball, every `.dxt`, and the checksum
     file (OIDC token from GitHub Actions; identity is the workflow path
     at the tag ref).
   - Generates a SLSA L3 provenance attestation
     (`multiple.intoto.jsonl`) via the `slsa-framework/slsa-github-generator`
     reusable workflow.
   - Re-runs `cosign verify-blob` and `slsa-verifier verify-artifact`
     in a separate verification job for every tarball and `.dxt` before
     the GitHub Release draft is created. The verify job pulls the
     `signed-bundle` and SLSA provenance artifacts directly from the
     workflow's artifact storage. If either check fails, the workflow
     fails before any draft release assets exist.
   - Drafts the GitHub Release with all artifacts attached, then downloads
     each draft asset by release-asset ID and compares the exact filename
     inventory, byte size, and sha256 against the signed `dist/` payload.
5. **Install-test the draft release.** After `release.yml` has created the
   verified draft, run `release-install.yml` from the tag ref before making
   the release public:
   ```sh
   gh workflow run release-install.yml --ref "$TAG" -f ref="$TAG"
   ```
   The workflow uses the repository token to download the draft tarballs and
   macOS `.dxt` assets, checks
   `sha256sums.txt`, verifies cosign signatures before extracting,
   rejects unsafe tar paths before unpacking, validates macOS code
   signatures, verifies macOS DXT package shape, and executes the shipped
   daemon/CLI/MCP smoke path on macOS arm64/x64 and Linux x64 glibc
   runners. Linux x64 musl and Linux arm64 release artifacts ship `cloak`
   and `cloakd` only, so those rows run daemon/CLI install checks and
   intentionally skip MCP smoke until native `cloak-mcp` packages exist. On
   success it uploads a
   `release-install-$TAG` marker artifact containing the tag name,
   resolved tag commit SHA, repository, workflow ref, GitHub Release ID,
   `sha256sums.txt` hash, and release asset ID/size manifest.
6. **Promote.** Publish through the marker-gated workflow, not the GitHub UI:
   ```sh
   gh workflow run publish-release.yml --ref "$TAG" -f ref="$TAG"
   ```
   The workflow refuses to publish unless `release-install.yml` has produced
   a matching marker for the same tag commit and the current draft release
   asset IDs/sizes plus `sha256sums.txt` hash. A GitHub UI publish bypasses
   that prevention path; `publish-release.yml` has a post-publish guard that
   fails visibly and attempts to restore draft status if someone publishes
   without the marker, but it cannot prevent the brief exposure window before
   the guard runs.
7. **Downstream taps and registries.** Run downstream publish workflows
   from the same tag ref, for example:
   ```sh
   gh workflow run homebrew-bump.yml --ref "$TAG" -f ref="$TAG"
   gh workflow run docker-push.yml --ref "$TAG" -f ref="$TAG"
   ```
   Stable Homebrew publishes fail if `HOMEBREW_TAP_TOKEN` is missing, and
   Homebrew/Docker both fail unless they can download and validate a
   matching `release-install-$TAG` marker for the same tag commit SHA and
   current GitHub Release asset binding.
   npm publishing is paused until the npm
   package ships audited native `cloak-mcp` binaries per supported platform.
8. **Docker.** `docker-push.yml` builds a multi-arch (`linux/amd64`,
   `linux/arm64`) `cloakd` image and pushes to GHCR. `:X.Y.Z` is always
   pushed. `:X.Y` and `:latest` are appended only when the tag has no
   SemVer prerelease segment, so any hyphenated tag like `v0.9.0-rc1`
   or `v1.0.1-hotfix` does not advance stable channels.
   The manifest is assembled from the immutable per-arch image digests,
   not mutable per-arch tags. The workflow cosign-signs the immutable
   multi-arch manifest digest and verifies that digest plus every pushed
   tag before completing.

Production tags are plain `vMAJOR.MINOR.PATCH` tags with no hyphenated
SemVer prerelease segment. Any accepted tag containing `-`, including
`v0.9.0-rc1` or `v1.0.1-hotfix`, is treated as a prerelease by the
release, Docker, and Homebrew workflows. Production macOS rows must be
signed and notarized; the workflow fails if the Apple secrets listed
below are missing. Prerelease/fork preview tags may skip Apple
signing/notarization, but those macOS artifacts are explicitly unsigned
and should not be marketed as production builds.

## macOS notarization

Stable production macOS binaries (`cloak`, `cloakd`, `cloak-mcp`) must be
Developer ID signed and submitted to Apple's notary service via the
`release.yml` flow. The workflow refuses to build a production macOS
tarball if any required Apple secret is absent.

Prerelease/fork preview tags may skip this flow when the secrets are not
available. Those artifacts are unsigned/unnotarized previews and can
require `xattr -d com.apple.quarantine` after download.

Bare command-line Mach-O binaries cannot be stapled in-place like `.pkg`,
`.dmg`, or `.app` bundles. The workflow still submits the signed binaries
to Apple's notary service; Gatekeeper may need an online ticket lookup on
first launch. A future packaged installer can provide an offline-stapled
ticket.

macOS trust prompts and Background Items use the Developer ID certificate
subject as the displayed developer name. With the current individual
Developer ID this can show "Varun Menon"; changing that requires an Apple
organization account and a new certificate.

The pipeline, per macOS row:

1. Decodes the Developer ID Application `.p12` from
   `secrets.APPLE_CERT_P12_BASE64` into a throwaway keychain.
2. `codesign --force --options runtime --timestamp --sign "Developer ID
   Application: <NAME> (<TEAM_ID>)"` over each Mach-O binary.
3. Zips the signed binaries and submits the zip via
   `xcrun notarytool submit --wait` using an App Store Connect API key
   (`secrets.APPLE_API_KEY_BASE64` / `APPLE_API_KEY_ID` /
   `APPLE_API_KEY_ISSUER_ID`).
4. Attempts `xcrun stapler staple` on each binary and logs a notice when
   stapler rejects a bare Mach-O. In that case the notarization ticket is
   served by Apple online during Gatekeeper's first-launch check.
5. Tarballs the signed/notarized binaries.
6. **After** notarization, the cosign keyless `sign` job signs the
   final tarball, so the cosign certificate covers the notarized bytes
   the user actually downloads.

If any required Apple secret is empty on a production tag, the macOS row
fails. If any required Apple secret is empty on a prerelease tag, the row
logs a `::warning::`, skips signing/notarization, and produces an
unsigned preview tarball.

### Required GitHub Secrets

Add these in **Settings → Secrets and variables → Actions** for the
`cloakward/cloak` repo:

| Secret | What it is | Where to get it |
| --- | --- | --- |
| `APPLE_CERT_P12_BASE64` | Developer ID Application cert + private key as a `.p12`, then `base64 -i cert.p12 \| pbcopy` | Keychain Access → "My Certificates" → right-click "Developer ID Application: <NAME> (<TEAM_ID>)" → Export → `.p12` |
| `APPLE_CERT_PASSWORD` | The password you set when exporting the `.p12` | You picked it during the export above |
| `APPLE_API_KEY_BASE64` | The App Store Connect API `.p8` private key, base64-encoded (`base64 -i AuthKey_XXXXXXXX.p8 \| pbcopy`) | https://appstoreconnect.apple.com/access/api → Keys → "+" → role **Developer** → download (one-time download!) |
| `APPLE_API_KEY_ID` | 10-character alphanumeric Key ID | Shown next to the key on the App Store Connect Keys page |
| `APPLE_API_KEY_ISSUER_ID` | UUID Issuer ID | Shown at the top of the App Store Connect Keys page |
| `APPLE_TEAM_ID` | 10-character team ID | https://developer.apple.com/account → Membership details |

### Generating the Developer ID Application certificate

If you don't already have one:

1. https://developer.apple.com/account → Certificates → "+" → **Developer ID Application**.
2. Generate a CSR via Keychain Access → Certificate Assistant → "Request a Certificate from a Certificate Authority" (save to disk).
3. Upload the CSR, download the issued `.cer`, double-click to install in your login keychain.
4. In Keychain Access, expand the certificate to reveal its private key, select both, right-click → **Export 2 items** → `.p12`. Set a password (this becomes `APPLE_CERT_PASSWORD`).
5. `base64 -i cert.p12 | pbcopy` and paste into `APPLE_CERT_P12_BASE64`.

### Generating the App Store Connect API key

`notarytool` accepts API keys instead of an Apple-ID-and-password
combo (more robust, no 2FA prompts, can be revoked individually):

1. https://appstoreconnect.apple.com/access/api → **Keys** tab.
2. Click **+** → name it "Cloak notarytool" → **Access: Developer** is sufficient.
3. **Download the `.p8`** — this is the only chance you get; the file disappears from the UI immediately after download.
4. Note the **Key ID** (10 chars) and the **Issuer ID** (UUID at the top of the page).
5. `base64 -i AuthKey_<KEY_ID>.p8 | pbcopy` → `APPLE_API_KEY_BASE64`.

## Moving inputs to review before production

Some inputs are intentionally still moving or externally resolved:

- GitHub Actions in release, install-test, Docker, Homebrew, npm cleanup,
  CI, smoke, and security workflows are pinned to immutable commit SHAs.
  When bumping an action, resolve the tag to a new commit SHA in the same
  change and review the upstream release notes.
- The Rust toolchain follows `rust-toolchain.toml` (currently `1.94.1`).
- Docker image builds use pinned base-image digests and a pinned Debian
  snapshot timestamp (`DEBIAN_SNAPSHOT` in `Dockerfile`) for builder packages
  (`pkg-config`, `ca-certificates`, `curl`, `build-essential`, `clang`). Bump
  that timestamp only in a reviewed change and rebuild from a new tag.
- `libsodium-sys-stable/fetch-latest` is disabled; release, CI, smoke, and
  Docker builds run `scripts/prepare-libsodium-dist.sh` and build from the
  versioned `libsodium-1.0.21-stable.tar.gz` archive pinned by SHA-256 via
  `SODIUM_DIST_DIR`.

Bun was an obvious `latest` input and is pinned to `1.2.9` in CI/release
workflows. Before cutting a production tag, review the remaining moving
inputs in the workflow run summary, Cargo build output, and Docker build
log. Do not publish a production release if an unexpected action,
toolchain, apt-package, or base-image update landed in the same run; either
pin it first or cut a new tag after review. A libsodium version bump must
update both the versioned archive name and pinned SHA-256 values in
`scripts/prepare-libsodium-dist.sh`.

## What a release publishes

Every Cloak release tag (`vX.Y.Z`) cut by the current workflow is built,
signed, and provenance-attested by `.github/workflows/release.yml`. Each
platform tarball ships with:

- `cloak-<version>-<target>.tar.gz` — the release archive
- `cloak-<version>-<target>.tar.gz.sig` — cosign keyless signature
- `cloak-<version>-<target>.tar.gz.cert` — cosign Fulcio certificate

Claude Desktop extension packages ship for macOS arm64/x64:

- `Cloak-<version>-<platform>.dxt` — Claude Desktop extension archive
- `Cloak-<version>-<platform>.dxt.sig` — cosign keyless signature
- `Cloak-<version>-<platform>.dxt.cert` — cosign Fulcio certificate

Plus, attached once per release:

- `sha256sums.txt` (and `.sig` / `.cert`) — aggregate hash file covering
  tarballs and `.dxt` packages
- `multiple.intoto.jsonl` — SLSA L3 provenance attestation

Older preview releases may include `.dxt` files without matching `.sig`,
`.cert`, or SLSA subject entries. Treat those `.dxt` files as unsigned
convenience assets.

## Prerequisites

```sh
brew install cosign slsa-verifier
# or: go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest
```

## Verify cosign signature

Pick a tag, e.g. `v1.0.0`, and a target, e.g. `aarch64-apple-darwin`:

```sh
TAG=v1.0.0
TARGET=aarch64-apple-darwin
gh release download "$TAG" --pattern "cloak-${TAG#v}-${TARGET}.tar.gz*"
gh release download "$TAG" --pattern 'sha256sums.txt*'
gh release download "$TAG" --pattern 'multiple.intoto.jsonl'

cosign verify-blob \
  --certificate "cloak-${TAG#v}-${TARGET}.tar.gz.cert" \
  --signature   "cloak-${TAG#v}-${TARGET}.tar.gz.sig" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity "https://github.com/cloakward/cloak/.github/workflows/release.yml@refs/tags/${TAG}" \
  "cloak-${TAG#v}-${TARGET}.tar.gz"
```

The verifier prints `Verified OK` on success.

For a `.dxt`, use the same command shape with the `.dxt` filename and its
matching `.dxt.sig` / `.dxt.cert` files.

## Verify SLSA L3 provenance

```sh
slsa-verifier verify-artifact \
  --provenance-path multiple.intoto.jsonl \
  --source-uri "github.com/cloakward/cloak" \
  --source-tag "$TAG" \
  "cloak-${TAG#v}-${TARGET}.tar.gz"
```

A passing run binds the artifact's sha256 to a specific GitHub Actions
build of `release.yml` at the tagged commit — proof the tarball or `.dxt`
was produced by the release pipeline and not tampered with after.

## Cross-check the aggregate hash file

```sh
sha256sum -c sha256sums.txt --ignore-missing
```
