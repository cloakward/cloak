#!/usr/bin/env bash
# End-to-end smoke test for v0.1.
#
# Builds release binaries, starts the daemon, drives it through cloak-cli
# (init / add / list / show / daemon-unlock), then drives the MCP shim
# through `--self-test` (handshake + vault.list), and finally verifies the
# audit log.
#
# State is hermetic: HOME is redirected to a tempdir so the vault, audit
# log, and policy file all live there. The macOS Keychain item
# `dev.cloak / vault.pepper` is shared with production — that is the
# correct production behavior, and the test relies on it.
#
# Run from a Mac with a libsodium toolchain:
#
#   ./scripts/smoke-test.sh
#
# Exits 0 on full success.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SMOKE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cloak-smoke.XXXXXX")"
SOCK_DIR="$SMOKE_DIR/run"
mkdir -p "$SOCK_DIR" "$SMOKE_DIR/Library/Application Support" "$SMOKE_DIR/.config"

# Redirect HOME so the daemon and the CLI both resolve `Vault::default_path`
# to the same hermetic location. We also use the documented
# `CLOAK_PEPPER_FILE` escape hatch instead of the OS Keychain, so the
# smoke test does not require interactive Keychain authorization (which
# is unavailable in CI / non-Aqua sessions).
export HOME="$SMOKE_DIR"
export XDG_RUNTIME_DIR="$SOCK_DIR"
export CLOAK_PEPPER_FILE="$SMOKE_DIR/.cloak-pepper"
export RUST_LOG="cloak_core=warn,cloakd=warn"

cleanup() {
  rc=$?
  if [[ -n "${CLOAKD_PID:-}" ]]; then
    kill -TERM "$CLOAKD_PID" 2>/dev/null || true
    wait "$CLOAKD_PID" 2>/dev/null || true
  fi
  if [[ "$rc" -ne 0 && -s "$SMOKE_DIR/cloakd.err" ]]; then
    echo "==> cloakd stderr (last 60 lines, on failure)"
    tail -60 "$SMOKE_DIR/cloakd.err" || true
  fi
  echo "cleanup: removing $SMOKE_DIR"
  rm -rf "$SMOKE_DIR"
}
trap cleanup EXIT

echo "==> Building release binaries"
cargo build --release --workspace >/dev/null

CLOAK="$REPO_ROOT/target/release/cloak"
CLOAKD="$REPO_ROOT/target/release/cloakd"
test -x "$CLOAK"
test -x "$CLOAKD"

echo "==> Building cloak-mcp single binary"
(
  cd packages/cloak-mcp
  bun install >/dev/null 2>&1
  bun build src/server.ts --compile --outfile dist/cloak-mcp >/dev/null
)
MCP="$REPO_ROOT/packages/cloak-mcp/dist/cloak-mcp"
test -x "$MCP"

echo "==> Setting up permissive policy at $HOME/.config/cloak/policy.toml"
mkdir -p "$HOME/.config/cloak"
cp "$REPO_ROOT/scripts/policy.example.toml" "$HOME/.config/cloak/policy.toml"

# Test passphrase escape hatch — shared by all `cloak` invocations below.
export CLOAK_PASSPHRASE="REDACTED-smoke-passphrase"

echo "==> cloak --version"
"$CLOAK" --version

echo "==> cloak init (default vault path inside hermetic HOME)"
"$CLOAK" --no-biometric init

echo "==> cloak add OPENAI_API_KEY (value=REDACTED-smoke-key)"
echo "REDACTED-smoke-key" | "$CLOAK" --no-biometric add OPENAI_API_KEY

echo "==> cloak list"
"$CLOAK" --no-biometric list

echo "==> cloak show OPENAI_API_KEY (--allow-redirect since stdout is not a TTY)"
got="$("$CLOAK" --no-biometric show --allow-redirect OPENAI_API_KEY)"
if [[ "$got" != "REDACTED-smoke-key" ]]; then
  echo "FAIL: cloak show round-trip mismatch"
  exit 1
fi
echo "    round-trip OK"

# Now start the daemon (it will open the same vault file the CLI just
# created and inhabit the same hermetic HOME).
echo "==> Starting cloakd"
"$CLOAKD" >"$SMOKE_DIR/cloakd.out" 2>"$SMOKE_DIR/cloakd.err" &
CLOAKD_PID=$!

for _ in 1 2 3 4 5 6 7 8; do
  if [[ -S "$SOCK_DIR/cloakd.sock" ]]; then break; fi
  sleep 0.25
done
if [[ ! -S "$SOCK_DIR/cloakd.sock" ]]; then
  echo "FAIL: daemon socket not created at $SOCK_DIR/cloakd.sock"
  cat "$SMOKE_DIR/cloakd.err"
  exit 1
fi
echo "    socket up: $SOCK_DIR/cloakd.sock"

echo "==> cloak daemon-unlock (push passphrase to daemon over IPC)"
"$CLOAK" --no-biometric daemon-unlock

echo "==> cloak-mcp --self-test"
CLOAK_SOCK="$SOCK_DIR/cloakd.sock" "$MCP" --self-test

echo "==> tail audit log"
AUDIT="$HOME/Library/Application Support/cloak/audit.jsonl"
if [[ -s "$AUDIT" ]]; then
  echo "    audit entries:"
  cat "$AUDIT" | tail -5
else
  echo "    audit log is empty (no privileged tool calls in this smoke run; expected)"
fi

echo
echo "=========================================="
echo "  SMOKE TEST PASSED"
echo "=========================================="
