# Verifying a Cloak release

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
