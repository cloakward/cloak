#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <release-tag>" >&2
  exit 2
fi

TAG="$1"
if ! printf '%s' "$TAG" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
  echo "::error::ref must be a SemVer release tag like v1.2.3 or v1.2.3-rc1"
  exit 1
fi

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"

marker="release-install-${TAG}"
tag_sha="$(git rev-list -n 1 "$TAG")"
if [ -z "$tag_sha" ]; then
  echo "::error::could not resolve ${TAG}"
  exit 1
fi

expected_workflow_ref="${GITHUB_REPOSITORY}/.github/workflows/release-install.yml@refs/tags/${TAG}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

release_json="$(gh api "repos/${GITHUB_REPOSITORY}/releases/tags/${TAG}")"
release_id="$(jq -r '.id' <<<"$release_json")"
if [ -z "$release_id" ] || [ "$release_id" = "null" ]; then
  echo "::error::could not resolve release id for ${TAG}"
  exit 1
fi

sha_asset_id="$(jq -r '.assets[] | select(.name == "sha256sums.txt") | .id' <<<"$release_json" | head -n1)"
if [ -z "$sha_asset_id" ] || [ "$sha_asset_id" = "null" ]; then
  echo "::error::release ${TAG} is missing sha256sums.txt"
  exit 1
fi

gh api \
  -H "Accept: application/octet-stream" \
  "repos/${GITHUB_REPOSITORY}/releases/assets/${sha_asset_id}" \
  > "$tmp/current-sha256sums.txt"
sha256sums_sha256="$(sha256sum "$tmp/current-sha256sums.txt" | awk '{print $1}')"

# The SLSA provenance file is the one asset NOT covered by sha256sums.txt
# (it cannot attest itself). Bind it by content hash so a same-size forgery
# of multiple.intoto.jsonl cannot pass while the install marker still matches.
prov_asset_id="$(jq -r '.assets[] | select(.name == "multiple.intoto.jsonl") | .id' <<<"$release_json" | head -n1)"
if [ -z "$prov_asset_id" ] || [ "$prov_asset_id" = "null" ]; then
  echo "::error::release ${TAG} is missing multiple.intoto.jsonl"
  exit 1
fi
gh api \
  -H "Accept: application/octet-stream" \
  "repos/${GITHUB_REPOSITORY}/releases/assets/${prov_asset_id}" \
  > "$tmp/current-multiple.intoto.jsonl"
provenance_sha256="$(sha256sum "$tmp/current-multiple.intoto.jsonl" | awk '{print $1}')"

assets="$(jq -c '[.assets[] | {name, id:(.id|tostring), size:(.size|tostring)}] | sort_by(.name)' <<<"$release_json")"
version="${TAG#v}"
{
  for target in \
    aarch64-apple-darwin \
    x86_64-apple-darwin \
    x86_64-unknown-linux-gnu \
    x86_64-unknown-linux-musl \
    aarch64-unknown-linux-gnu
  do
    printf 'cloak-%s-%s.tar.gz\n' "$version" "$target"
    printf 'cloak-%s-%s.tar.gz.sig\n' "$version" "$target"
    printf 'cloak-%s-%s.tar.gz.cert\n' "$version" "$target"
  done
  for platform in macos-arm64 macos-x64; do
    printf 'Cloak-%s-%s.dxt\n' "$version" "$platform"
    printf 'Cloak-%s-%s.dxt.sig\n' "$version" "$platform"
    printf 'Cloak-%s-%s.dxt.cert\n' "$version" "$platform"
  done
  printf '%s\n' \
    sha256sums.txt \
    sha256sums.txt.sig \
    sha256sums.txt.cert \
    multiple.intoto.jsonl
} | sort > "$tmp/expected-assets.txt"
jq -r '.assets[].name' <<<"$release_json" | sort > "$tmp/actual-assets.txt"
if ! diff -u "$tmp/expected-assets.txt" "$tmp/actual-assets.txt"; then
  echo "::error::release ${TAG} asset inventory includes missing or unexpected assets"
  exit 1
fi

found="false"
while IFS= read -r run_id; do
  [ -n "$run_id" ] || continue
  while IFS= read -r artifact_id; do
    [ -n "$artifact_id" ] || continue

    gh api \
      -H "Accept: application/zip" \
      "repos/${GITHUB_REPOSITORY}/actions/artifacts/${artifact_id}/zip" \
      > "$tmp/marker.zip"
    if ! unzip -p "$tmp/marker.zip" "release-install-${TAG}.json" > "$tmp/marker.json"; then
      echo "::warning::release-install marker artifact ${artifact_id} did not contain release-install-${TAG}.json"
      continue
    fi

    if jq -e \
      --arg tag "$TAG" \
      --arg tag_sha "$tag_sha" \
      --arg repository "$GITHUB_REPOSITORY" \
      --arg workflow_ref "$expected_workflow_ref" \
      --arg release_id "$release_id" \
      --arg sha256sums_sha256 "$sha256sums_sha256" \
      --arg provenance_sha256 "$provenance_sha256" \
      --argjson assets "$assets" \
      '.tag == $tag and .tag_sha == $tag_sha and .repository == $repository and .workflow_ref == $workflow_ref and .release_id == $release_id and .sha256sums_sha256 == $sha256sums_sha256 and .provenance_sha256 == $provenance_sha256 and .assets == $assets' \
      "$tmp/marker.json" >/dev/null
    then
      echo "Found verified release-install marker ${marker} on run ${run_id}"
      found="true"
      break 2
    fi
  done < <(
    gh api --paginate \
      "repos/${GITHUB_REPOSITORY}/actions/runs/${run_id}/artifacts?per_page=100" \
      --jq ".artifacts[] | select(.name == \"${marker}\" and .expired == false) | .id"
  )
done < <(
  gh api --paginate \
    "repos/${GITHUB_REPOSITORY}/actions/workflows/release-install.yml/runs?event=workflow_dispatch&status=success&per_page=100" \
    --jq '.workflow_runs[].id'
)

if [ "$found" != "true" ]; then
  echo "::error::missing matching release-install marker ${marker} for tag sha ${tag_sha} and current release assets; run: gh workflow run release-install.yml --ref ${TAG} -f ref=${TAG}"
  exit 1
fi
