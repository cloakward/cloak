#!/usr/bin/env bash
# Regenerate docs/cloak-demo.gif from docs/demo.tape.
#
# Renders against a fully hermetic, throwaway vault (temp HOME + a 0600
# pepper file), so it never touches your real keychain or vault. Requires
# `vhs` (brew install vhs) plus release binaries.
#
#   ./scripts/render-demo.sh
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

command -v vhs >/dev/null 2>&1 || { echo "vhs not found — install with: brew install vhs"; exit 1; }

echo "==> building release cloak"
cargo build --release --bin cloak >/dev/null

DEMO_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cloak-demo.XXXXXX")"
# VHS runs the tape from the repo root, so the tape's `echo ... >> .env`
# lands here; clean it up (and the temp vault) on exit.
trap 'rm -rf "$DEMO_DIR"; rm -f "$REPO_ROOT/.env"' EXIT
mkdir -p "$DEMO_DIR/Library/Application Support" "$DEMO_DIR/.config/cloak"
cp scripts/policy.example.toml "$DEMO_DIR/.config/cloak/policy.toml"

export HOME="$DEMO_DIR"
export CLOAK_PEPPER_FILE="$DEMO_DIR/.cloak-pepper"
export PATH="$REPO_ROOT/target/release:$PATH"
# Black-and-white prompt: a gray `$` with a leading blank line, so every
# command gets breathing room above (and after the prior command's output).
export PS1='\n\[\e[38;5;245m\]$\[\e[0m\] '

# Vault passphrase the tape types at the prompt. Must match docs/demo.tape.
PASSPHRASE="demo-passphrase-not-secret"

echo "==> initializing throwaway vault"
CLOAK_UNSAFE_TEST_MODE=1 CLOAK_PASSPHRASE="$PASSPHRASE" CLOAK_ALLOW_MNEMONIC_STDOUT=1 \
  cloak --no-biometric init >/dev/null 2>&1

# Render with a clean env (no CLOAK_PASSPHRASE) so `cloak add` shows the real
# interactive passphrase prompt rather than a test-mode banner.
echo "==> rendering docs/cloak-demo.gif"
vhs docs/demo.tape

echo "==> done: docs/cloak-demo.gif ($(du -h docs/cloak-demo.gif | cut -f1))"
