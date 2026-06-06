#!/usr/bin/env node
// Cloak.dxt first-run handler.
//
// Invoked by the bundled cloak-mcp binary on first activation when
// cloakd cannot be reached. This script intentionally does not run
// `cloak setup`: setup creates a one-time recovery seed that must be
// shown and verified in a terminal, not hidden inside an extension host.
//
// Contract:
//   - exit 2  => setup is required; cloak-mcp surfaces the error to the host.
//
// Requirements:
//   - `cloak` installed at CLOAK_CLI, a standard install path, or a vetted
//     absolute PATH entry. If absent, the fallback dialog directs the user
//     to https://github.com/cloakward/cloak#install.

const { spawnSync } = require("node:child_process");
const {
  accessSync,
  constants,
  realpathSync,
  statSync,
} = require("node:fs");
const path = require("node:path");

const INSTALL_URL = "https://github.com/cloakward/cloak#install";
const CLOAK_EXE = process.platform === "win32" ? "cloak.exe" : "cloak";
const TRUSTED_CLOAK_PATHS = [
  process.env.CLOAK_CLI,
  ...(process.env.CLOAK_DXT_CLOAK_PATHS || "").split(path.delimiter),
  "/opt/homebrew/bin/cloak",
  "/usr/local/bin/cloak",
  "/usr/bin/cloak",
  "/bin/cloak",
  "/opt/cloak/bin/cloak",
].filter(Boolean);

function isExecutableFile(file) {
  const st = statSync(file);
  if (!st.isFile()) return false;
  accessSync(file, constants.X_OK);
  return true;
}

function currentGroups() {
  return typeof process.getgroups === "function" ? process.getgroups() : [];
}

function trustedExecutableMode(mode) {
  return (mode & 0o022) === 0;
}

function trustedDirectoryMode(mode, gid) {
  if ((mode & 0o002) !== 0) return false;
  if ((mode & 0o020) === 0) return true;

  // Apple Silicon Homebrew normally lives under /opt/homebrew with
  // admin-group-writable directories. That is the documented install path, so
  // accept that specific macOS group while still rejecting world-writable dirs
  // and group-writable dirs owned by broad groups like staff.
  return process.platform === "darwin" && gid === 80 && currentGroups().includes(gid);
}

function trustedExecutable(file) {
  if (!file || !path.isAbsolute(file)) return null;
  try {
    const resolved = realpathSync(file);
    const fileStat = statSync(resolved);
    if (!isExecutableFile(resolved)) return null;
    const uid = typeof process.getuid === "function" ? process.getuid() : null;
    if (uid !== null && fileStat.uid !== 0 && fileStat.uid !== uid) return null;
    if (!trustedExecutableMode(fileStat.mode)) return null;

    let dir = path.dirname(resolved);
    while (true) {
      const dirStat = statSync(dir);
      if (uid !== null && dirStat.uid !== 0 && dirStat.uid !== uid) return null;
      if (!trustedDirectoryMode(dirStat.mode, dirStat.gid)) return null;
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }

    return resolved;
  } catch {
    return null;
  }
}

function findOnPath(bin) {
  for (const dir of (process.env.PATH || "").split(path.delimiter)) {
    if (!dir || !path.isAbsolute(dir)) continue;
    const candidate = trustedExecutable(path.join(dir, bin));
    if (candidate) return candidate;
  }
  return null;
}

function nativeDialog(title, message) {
  if (process.env.CLOAK_DXT_SUPPRESS_DIALOGS === "1") {
    process.stderr.write(`[${title}] ${message}\n`);
    return;
  }
  // Best-effort, OS-native, no extra deps.
  if (process.platform === "darwin") {
    const osascript = trustedExecutable("/usr/bin/osascript");
    if (osascript) {
      const script = `display dialog ${JSON.stringify(message)} with title ${JSON.stringify(title)} buttons {"OK"} default button "OK"`;
      spawnSync(osascript, ["-e", script], { stdio: "ignore" });
      return;
    }
  }
  if (process.platform === "linux") {
    for (const tool of ["zenity", "kdialog", "notify-send"]) {
      const dialogTool = findOnPath(tool);
      if (!dialogTool) continue;
      if (tool === "zenity") {
        spawnSync(dialogTool, ["--info", `--title=${title}`, `--text=${message}`], { stdio: "ignore" });
        return;
      }
      if (tool === "kdialog") {
        spawnSync(dialogTool, ["--title", title, "--msgbox", message], { stdio: "ignore" });
        return;
      }
      spawnSync(dialogTool, [title, message], { stdio: "ignore" });
      return;
    }
  }
  // Last resort: stderr. Claude Desktop surfaces stderr in the extension panel.
  process.stderr.write(`[${title}] ${message}\n`);
}

function findCloak() {
  for (const candidate of TRUSTED_CLOAK_PATHS) {
    const trusted = trustedExecutable(candidate);
    if (trusted) return trusted;
  }

  return findOnPath(CLOAK_EXE);
}

function main() {
  const cloakBin = findCloak();
  if (!cloakBin) {
    nativeDialog(
      "Cloak: install required",
      `Cloak's CLI is not installed.\n\nInstall it from ${INSTALL_URL}, then restart Claude Desktop.`,
    );
    process.exit(2);
  }

  nativeDialog(
    "Cloak: terminal setup required",
    `Cloak is installed at ${cloakBin}, but the extension cannot safely initialize a vault because the one-time recovery seed must be shown in a terminal.\n\nOpen a terminal, run \`cloak setup\`, write down and verify the recovery seed, then run \`cloak daemon start\` and \`cloak unlock\`. Restart Claude Desktop after the daemon is running and unlocked.`,
  );
  process.exit(2);
}

main();
