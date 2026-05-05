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
   - Builds the release artifacts in a matrix (macOS arm64/x64, Linux musl
     amd64/arm64; Windows is deferred to v1.0.1 — see
     [issue #3](https://github.com/cloakward/cloak/issues/3)).
   - Tarballs each row as `cloak-X.Y.Z-<target>.tar.gz`.
   - Aggregates `sha256sums.txt`.
   - Cosign-keyless-signs every tarball and the checksum file (OIDC token
     from GitHub Actions; identity is the workflow path at the tag ref).
   - Generates a SLSA L3 provenance attestation
     (`multiple.intoto.jsonl`) via the `slsa-framework/slsa-github-generator`
     reusable workflow.
   - Re-runs `cosign verify-blob` and `slsa-verifier verify-artifact`
     against the drafted artifacts in a separate verification job. If
     either fails, the release is not published.
   - Drafts the GitHub Release with all artifacts attached.
5. **Promote.** Once the verification job is green and you've eyeballed the
   draft, click `Publish release` in the GitHub UI.
6. **Downstream taps and registries.** Tagging triggers
   `homebrew-bump.yml` (Formula PR to `homebrew-cloak`) and
   `npm-publish.yml` (`@cloak-ward/mcp` to npm via trusted publishing).
7. **Docker.** `docker-push.yml` builds a multi-arch (`linux/amd64`,
   `linux/arm64`) `cloakd` image and pushes to GHCR with `:X.Y.Z`,
   `:X.Y`, and `:latest` tags.

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
