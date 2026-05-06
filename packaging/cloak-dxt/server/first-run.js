#!/usr/bin/env node
// Cloak.dxt first-run handler.
//
// Invoked by the bundled cloak-mcp binary on first activation when
// CLOAK_DXT_FIRST_RUN points here. Walks the user through `cloak setup`
// via OS-native dialogs. Does NOT bypass biometric / passphrase prompts —
// `cloak setup` (PR 2) drives those itself; this script only shells out to
// it and reports failure via a fallback dialog.
//
// Contract:
//   - exit 0     => setup ran (or was already done); cloak-mcp continues.
//   - exit != 0  => setup failed; cloak-mcp surfaces the error to the host.
//
// Requirements:
//   - `cloak` binary on PATH. If absent, the fallback dialog directs the
//     user to https://cloakward.dev/install.

const { execFileSync, spawnSync } = require("node:child_process");
const { existsSync } = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const MARKER = path.join(os.homedir(), ".config", "cloak", ".dxt-setup-complete");
const INSTALL_URL = "https://cloakward.dev/install";

function which(bin) {
  const probe = process.platform === "win32" ? "where" : "command";
  const args = process.platform === "win32" ? [bin] : ["-v", bin];
  const r = spawnSync(probe, args, { stdio: ["ignore", "pipe", "ignore"] });
  if (r.status === 0) return r.stdout.toString().trim().split(/\r?\n/)[0] || null;
  return null;
}

function nativeDialog(title, message) {
  // Best-effort, OS-native, no extra deps.
  if (process.platform === "darwin") {
    const script = `display dialog ${JSON.stringify(message)} with title ${JSON.stringify(title)} buttons {"OK"} default button "OK"`;
    spawnSync("osascript", ["-e", script], { stdio: "ignore" });
    return;
  }
  if (process.platform === "linux") {
    for (const tool of ["zenity", "kdialog", "notify-send"]) {
      if (!which(tool)) continue;
      if (tool === "zenity") {
        spawnSync(tool, ["--info", `--title=${title}`, `--text=${message}`], { stdio: "ignore" });
        return;
      }
      if (tool === "kdialog") {
        spawnSync(tool, ["--title", title, "--msgbox", message], { stdio: "ignore" });
        return;
      }
      spawnSync(tool, [title, message], { stdio: "ignore" });
      return;
    }
  }
  // Last resort: stderr. Claude Desktop surfaces stderr in the extension panel.
  process.stderr.write(`[${title}] ${message}\n`);
}

function main() {
  if (existsSync(MARKER)) {
    process.exit(0);
  }

  const cloakBin = which("cloak");
  if (!cloakBin) {
    nativeDialog(
      "Cloak: install required",
      `Cloak's CLI is not installed.\n\nInstall it from ${INSTALL_URL}, then restart Claude Desktop.`,
    );
    process.exit(2);
  }

  // Hand control to `cloak setup`. PR 2 owns the dialog flow (biometric /
  // passphrase prompts via the OS native APIs). We just exec and inherit
  // its exit code.
  try {
    execFileSync(cloakBin, ["setup", "--from-dxt"], {
      stdio: "inherit",
      env: { ...process.env, CLOAK_INVOKED_FROM: "dxt" },
    });
    process.exit(0);
  } catch (err) {
    nativeDialog(
      "Cloak: setup failed",
      `\`cloak setup\` exited with status ${err.status ?? "unknown"}.\n\nOpen a terminal and run \`cloak setup\` to see the full error, or visit ${INSTALL_URL}.`,
    );
    process.exit(err.status ?? 1);
  }
}

main();
