#!/usr/bin/env bash
# Builds Cloak-<version>-<platform>.dxt.
#
# A .dxt is a zip of packaging/cloak-dxt/ with a per-platform cloak-mcp
# binary placed at server/binaries/cloak-mcp. Anthropic's MCPB toolchain
# (`npx @anthropic-ai/mcpb pack`) does the same job; this script is the
# zero-dep equivalent so CI doesn't need npx.
#
# Usage:
#   scripts/build-dxt.sh <version> <platform-tag> <path-to-cloak-mcp-binary>
#
# Example:
#   scripts/build-dxt.sh 0.9.0-rc1 macos-arm64 \
#     packages/cloak-mcp/dist/cloak-mcp
#
# Output: dist/Cloak-<version>-<platform-tag>.dxt
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <version> <platform-tag> <cloak-mcp-binary>" >&2
  exit 2
fi

version="$1"
platform="$2"
mcp_bin="$3"

if [ ! -x "$mcp_bin" ] && [ ! -f "$mcp_bin" ]; then
  echo "error: cloak-mcp binary not found at $mcp_bin" >&2
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

# Sanity: manifest must be at the root of the archive.
test -f "$stage/manifest.json" || { echo "manifest.json missing"; exit 1; }

# Reproducible-ish zip: store mtimes from the manifest only.
( cd "$stage" && zip -qr "$out" . )

echo "Built $out"
ls -la "$out"
