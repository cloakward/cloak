# Cloak release process and verification

> Audience: maintainers cutting a release, and downstream users verifying
> one. The verification half (cosign + slsa-verifier) is what landed in
> W9b; the cutting-a-release half is documented here so a fresh
> contributor can do it without reverse-engineering the workflow.

## Cutting a release (maintainer steps)

1. **Land all the workstreams that should ship.** `beta` is the integration
   branch; releases are tagged off `beta` once CI is green.
2. **Bump the version.** Update `Cargo.toml::workspace.package.version` and
   `packages/cloak-mcp/package.json::version` to the new `X.Y.Z`. Update
   `CHANGELOG.md`: rename the `Unreleased` heading to `[X.Y.Z] — YYYY-MM-DD`
   and start a fresh `Unreleased` section.
3. **Tag.** `git tag -s vX.Y.Z -m "Cloak X.Y.Z"`, `git push origin vX.Y.Z`.
   The tag must point at a commit on `beta` (or `main`, once `beta` has
   been fast-forwarded).
4. **Watch `release.yml`.** The workflow:
   - Builds the release artifacts in a 5-row matrix:
     macOS arm64 (`macos-26`),
     macOS x86_64 (`macos-26-intel`, best-effort),
     Linux glibc x86_64 (`x86_64-unknown-linux-gnu`),
     Linux musl x86_64 (`x86_64-unknown-linux-musl`),
     Linux glibc arm64 (`aarch64-unknown-linux-gnu`).
     Windows is deferred to v1.0.1 — see
     [issue #2](https://github.com/cloakward/cloak/issues/2).
   - Tarballs each row as `cloak-X.Y.Z-<target>.tar.gz`.
   - Aggregates `sha256sums.txt`.
   - Cosign-keyless-signs every tarball and the checksum file (OIDC token
     from GitHub Actions; identity is the workflow path at the tag ref).
   - Generates a SLSA L3 provenance attestation
     (`multiple.intoto.jsonl`) via the `slsa-framework/slsa-github-generator`
     reusable workflow.
   - Re-runs `cosign verify-blob` and `slsa-verifier verify-artifact`
     in a separate verification job. The verify job pulls the
     `signed-bundle` and SLSA provenance artifacts directly from the
     workflow's artifact storage (not from the draft release, since
     `gh release download` cannot see drafts). The bytes verified are
     identical to those uploaded to the draft. If either check fails,
     the workflow fails and the release stays in DRAFT.
   - Drafts the GitHub Release with all artifacts attached.
5. **Promote.** Once the verification job is green and you've eyeballed the
   draft, click `Publish release` in the GitHub UI.
6. **Downstream taps and registries.** Tagging triggers
   `homebrew-bump.yml` (Formula PR to `homebrew-cloak`) and
   `npm-publish.yml` (`@cloak-ward/mcp` to npm via trusted publishing).
7. **Docker.** `docker-push.yml` builds a multi-arch (`linux/amd64`,
   `linux/arm64`) `cloakd` image and pushes to GHCR. `:X.Y.Z` and
   `:X.Y` tags are always pushed; `:latest` is appended only when the
   release event flags `prerelease == false` (so a tag like
   `v0.9.0-rc1` does not advance `:latest` past production). The
   `prerelease` bit comes from `release.yml` passing `--prerelease`
   to `gh release create` whenever the tag matches `-rc*|-beta*|-alpha*`.

## macOS notarization

Starting with v1.0, macOS binaries (`cloak`, `cloakd`, `cloak-mcp`) ship
Apple-notarized via the Developer ID Application + `xcrun notarytool`
flow built into `release.yml`. End users no longer need to run
`xattr -d com.apple.quarantine` on the extracted tarballs.

The pipeline, per macOS row:

1. Decodes the Developer ID Application `.p12` from
   `secrets.APPLE_CERT_P12_BASE64` into a throwaway keychain.
2. `codesign --force --options runtime --timestamp --sign "Developer ID
   Application: <NAME> (<TEAM_ID>)"` over each Mach-O binary.
3. Zips the signed binaries and submits the zip via
   `xcrun notarytool submit --wait` using an App Store Connect API key
   (`secrets.APPLE_API_KEY_BASE64` / `APPLE_API_KEY_ID` /
   `APPLE_API_KEY_ISSUER_ID`).
4. Runs `xcrun stapler staple` on each binary. Bare Mach-O command-line
   tools cannot have a ticket stapled in-place (stapler only operates
   on bundles / dmgs / pkgs); for those Apple's CDN serves the
   notarization ticket online on first launch — same model as Homebrew
   bottles.
5. Tarballs the notarized binaries.
6. **After** notarization, the cosign keyless `sign` job signs the
   final tarball, so the cosign certificate covers the notarized bytes
   the user actually downloads.

If `secrets.APPLE_CERT_P12_BASE64` is empty (forks, dry-runs before the
secrets are added), every Apple step skips with a `::warning::` and the
tarballs ship unsigned — same Gatekeeper experience as v0.9.0-rc3.

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

## What a release publishes

Every Cloak release tag (`vX.Y.Z`) is built, signed, and provenance-attested
by `.github/workflows/release.yml`. Each platform tarball ships with:

- `cloak-<version>-<target>.tar.gz` — the release archive
- `cloak-<version>-<target>.tar.gz.sig` — cosign keyless signature
- `cloak-<version>-<target>.tar.gz.cert` — cosign Fulcio certificate

Plus, attached once per release:

- `sha256sums.txt` (and `.sig` / `.cert`) — aggregate hash file
- `multiple.intoto.jsonl` — SLSA L3 provenance attestation

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
  --certificate-identity-regexp "^https://github.com/cloakward/cloak/.github/workflows/release.yml@refs/tags/${TAG}$" \
  "cloak-${TAG#v}-${TARGET}.tar.gz"
```

The verifier prints `Verified OK` on success.

## Verify SLSA L3 provenance

```sh
slsa-verifier verify-artifact \
  --provenance-path multiple.intoto.jsonl \
  --source-uri "github.com/cloakward/cloak" \
  --source-tag "$TAG" \
  "cloak-${TAG#v}-${TARGET}.tar.gz"
```

A passing run binds the artifact's sha256 to a specific GitHub Actions
build of `release.yml` at the tagged commit — proof the binary was
produced by the release pipeline and not tampered with after.

## Cross-check the aggregate hash file

```sh
sha256sum -c sha256sums.txt --ignore-missing
```
