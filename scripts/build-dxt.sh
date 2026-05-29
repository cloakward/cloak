#!/usr/bin/env bash
# Builds Cloak-<version>-<platform>.dxt.
#
# A .dxt is a zip of packaging/cloak-dxt/ with a per-platform cloak-mcp
# binary placed at server/binaries/cloak-mcp. Anthropic's MCPB toolchain
# (`npx @anthropic-ai/mcpb pack`) does the same job; this script is the
# zero-dep equivalent so CI doesn't need npx.
#
# Usage:
#   scripts/build-dxt.sh <version> <platform-tag> <path-to-cloak-mcp-binary> [expected-version-output]
#
# Example:
#   scripts/build-dxt.sh 0.9.0-rc1 macos-arm64 \
#     packages/cloak-mcp/dist/cloak-mcp
#
# Output: dist/Cloak-<version>-<platform-tag>.dxt
set -euo pipefail

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  echo "usage: $0 <version> <platform-tag> <cloak-mcp-binary> [expected-version-output]" >&2
  exit 2
fi

version="$1"
platform="$2"
mcp_bin="$3"
expected_version_output="${4:-}"

case "$platform" in
  macos-arm64|macos-x64) package_os="darwin" ;;
  *)
    echo "error: unsupported DXT platform tag: $platform" >&2
    exit 2
    ;;
esac

if [ ! -x "$mcp_bin" ]; then
  echo "error: cloak-mcp binary not found or not executable at $mcp_bin" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
src="$repo_root/packaging/cloak-dxt"
out_dir="$repo_root/dist"
out="$out_dir/Cloak-${version}-${platform}.dxt"

mkdir -p "$out_dir"

# Stage in a temp dir so we don't pollute the source tree with the binary.
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

cp -R "$src/." "$stage/"
mkdir -p "$stage/server/binaries"
cp "$mcp_bin" "$stage/server/binaries/cloak-mcp"
chmod +x "$stage/server/binaries/cloak-mcp"
if [ -n "$expected_version_output" ]; then
  test "$expected_version_output" = "cloak-mcp $version" || {
    echo "error: cloak-mcp binary version does not match $version" >&2
    echo "actual: $expected_version_output" >&2
    exit 1
  }
else
  "$stage/server/binaries/cloak-mcp" --version | grep -F "cloak-mcp $version" >/dev/null || {
    echo "error: cloak-mcp binary version does not match $version" >&2
    exit 1
  }
fi

# Sanity: manifest must be at the root of the archive.
test -f "$stage/manifest.json" || { echo "manifest.json missing"; exit 1; }

node - "$stage/manifest.json" "$version" "$package_os" <<'NODE'
const fs = require("node:fs");

const [path, version, packageOs] = process.argv.slice(2);
const manifest = JSON.parse(fs.readFileSync(path, "utf8"));

function fail(message) {
  console.error(`error: ${message}`);
  process.exit(1);
}

if (manifest.mcpb_version) {
  fail("manifest uses invalid mcpb_version; use manifest_version");
}
if (manifest.manifest_version !== "0.3") {
  fail("manifest_version must be 0.3");
}
const mcpConfig = manifest.server?.mcp_config;
if (!mcpConfig?.platform_overrides) {
  fail("server.mcp_config.platform_overrides is required");
}
if (mcpConfig.platforms) {
  fail("server.mcp_config.platforms is invalid; use platform_overrides");
}
if (!mcpConfig.platform_overrides[packageOs]?.command) {
  fail(`platform_overrides.${packageOs}.command is required`);
}

manifest.version = version;
const cloakPrivacyUrl = `https://github.com/cloakward/cloak/blob/v${version}/docs/PRIVACY.md`;
const awsPrivacyUrl = "https://aws.amazon.com/privacy/";
const policies = Array.isArray(manifest.privacy_policies) ? manifest.privacy_policies : [];
const nonCloakPolicies = policies.filter(
  (policy) =>
    typeof policy === "string" &&
    !/^https:\/\/github\.com\/cloakward\/cloak\/blob\/[^/]+\/docs\/PRIVACY\.md$/.test(policy),
);
manifest.privacy_policies = [
  cloakPrivacyUrl,
  ...nonCloakPolicies.filter((policy, index, all) => all.indexOf(policy) === index),
];
if (!manifest.privacy_policies.includes(awsPrivacyUrl)) {
  manifest.privacy_policies.push(awsPrivacyUrl);
}
manifest.compatibility = {
  ...(manifest.compatibility || {}),
  platforms: [packageOs],
};
mcpConfig.platform_overrides = {
  [packageOs]: mcpConfig.platform_overrides[packageOs],
};
fs.writeFileSync(path, JSON.stringify(manifest, null, 2) + "\n");
NODE

manifest_version="$(node -e 'const fs = require("node:fs"); const [p] = process.argv.slice(1); process.stdout.write(JSON.parse(fs.readFileSync(p, "utf8")).version);' "$stage/manifest.json")"
test "$manifest_version" = "$version" || { echo "manifest version rewrite failed"; exit 1; }

# Reproducible-ish zip: normalize mtimes, omit extra file attrs, and feed
# sorted paths to zip.
find "$stage" -exec touch -t 202601010000.00 {} +
( cd "$stage" && find . -type f | LC_ALL=C sort | zip -X -q "$out" -@ )

echo "Built $out"
ls -la "$out"
