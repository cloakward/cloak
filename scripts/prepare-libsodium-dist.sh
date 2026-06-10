#!/usr/bin/env bash
# Download and pin the exact libsodium stable source archive expected by
# libsodium-sys-stable. Two independent checks gate the bytes that build:
#
#   1. This script verifies the SHA-256 of both the archive and its
#      minisign signature against the values pinned below, refusing to
#      proceed on any mismatch (defeats a moved/MITM'd upstream alias).
#   2. libsodium-sys-stable's build script then verifies the minisign
#      signature (LATEST.tar.gz.minisig) over the archive against
#      libsodium's embedded release public key — it carries the
#      `minisign-verify` build dependency for exactly this, and runs the
#      check unconditionally in the SODIUM_DIST_DIR path before extracting
#      and compiling.
#
# libsodium-sys-stable looks for files named LATEST.tar.gz and
# LATEST.tar.gz.minisig inside SODIUM_DIST_DIR. The upstream LATEST URL is a
# moving alias, so this script downloads an immutable versioned archive and
# stages it under the filenames the crate expects.
set -euo pipefail

out_dir="${1:-.cargo/libsodium-dist}"
base_url="https://download.libsodium.org/libsodium/releases"
source_archive="libsodium-1.0.21-stable.tar.gz"
source_signature="$source_archive.minisig"
archive_sha256="d7554ece208ff9a49b27ec9c82fd2c88058655fb8fbed2eebea6011048a24dfd"
signature_sha256="6b77537d2548c1a7ce6f4240add0e79f4ed0ac44d74b16abc5c2b5566b5d6e6e"

mkdir -p "$out_dir"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
    return
  fi
  shasum -a 256 "$1" | awk '{print $1}'
}

download() {
  local source_name="$1"
  local target_name="$2"
  local sha="$3"
  local path="$out_dir/$target_name"
  local tmp="$path.tmp"

  if [ -f "$path" ]; then
    actual="$(sha256_file "$path")"
    if [ "$actual" = "$sha" ]; then
      return
    fi
    echo "warning: replacing $target_name with pinned $source_name" >&2
  fi

  rm -f "$tmp"
  curl -fsSL "$base_url/$source_name" -o "$tmp"
  actual="$(sha256_file "$tmp")"
  if [ "$actual" != "$sha" ]; then
    rm -f "$tmp"
    echo "error: $source_name sha256 mismatch" >&2
    echo "expected: $sha" >&2
    echo "actual:   $actual" >&2
    echo "intentionally update scripts/prepare-libsodium-dist.sh if upstream source is being bumped" >&2
    exit 1
  fi
  mv "$tmp" "$path"
}

download "$source_archive" "LATEST.tar.gz" "$archive_sha256"
download "$source_signature" "LATEST.tar.gz.minisig" "$signature_sha256"

echo "libsodium dist ready: $out_dir"
