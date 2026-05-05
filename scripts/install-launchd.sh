#!/usr/bin/env bash
# Install cloakd as a per-user launchd agent on macOS.
# Usage: scripts/install-launchd.sh
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This script is for macOS. Linux uses systemd; Windows uses sc.exe." >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLOAKD_BIN="${CLOAKD_BIN:-$REPO_ROOT/target/release/cloakd}"

if [[ ! -x "$CLOAKD_BIN" ]]; then
  echo "cloakd binary not found at $CLOAKD_BIN" >&2
  echo "Build it first: cargo build --release -p cloak-core" >&2
  exit 1
fi

LOG_DIR="$HOME/Library/Logs/cloak"
PLIST_DIR="$HOME/Library/LaunchAgents"
PLIST_PATH="$PLIST_DIR/dev.cloak.cloakd.plist"
TEMPLATE="$REPO_ROOT/scripts/dev.cloak.cloakd.plist"

mkdir -p "$LOG_DIR" "$PLIST_DIR"

sed \
  -e "s|__CLOAKD_BIN__|$CLOAKD_BIN|g" \
  -e "s|__LOG_DIR__|$LOG_DIR|g" \
  "$TEMPLATE" > "$PLIST_PATH"

launchctl unload "$PLIST_PATH" 2>/dev/null || true
launchctl load -w "$PLIST_PATH"

echo "Installed and loaded: $PLIST_PATH"
echo "Logs: $LOG_DIR/"
echo "Tail: tail -f $LOG_DIR/cloakd.err.log"
