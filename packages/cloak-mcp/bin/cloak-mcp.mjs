#!/usr/bin/env node
// npm-only launcher for `cloak-mcp`.
//
// The actual server lives at ../src/server.ts and is written for the Bun
// runtime (TypeScript-native, top-level await, the @modelcontextprotocol/sdk
// import paths use .ts extensions). When Cloak is installed via
// `npm install -g @cloak-ward/mcp` we cannot ship a Node-runnable bundle
// without bringing along a full TS compile step, so this launcher does the
// minimum: detect `bun` on PATH and re-exec the server under it.
//
// Users who want a single statically-linked binary should install via
// Homebrew (`brew install cloakward/cloak/cloak`) or grab the platform
// tarball / .dxt from the GitHub Releases page; both of those use the
// `bun build --compile` path produced by .github/workflows/release.yml.

import { spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(__dirname, "..");
const SERVER_ENTRY = join(PKG_ROOT, "src", "server.ts");

function findBun() {
  // Prefer an explicit override (lets power users point at a pinned build).
  if (process.env.CLOAK_BUN && existsSync(process.env.CLOAK_BUN)) {
    return process.env.CLOAK_BUN;
  }
  // `bun --version` is the cheapest probe; rely on PATH resolution.
  const probe = spawnSync("bun", ["--version"], {
    stdio: "ignore",
    shell: false,
  });
  if (probe.status === 0) return "bun";
  return null;
}

function dieWithoutBun() {
  const msg = [
    "cloak-mcp: the npm package requires the Bun runtime to execute the",
    "TypeScript MCP server. `bun` was not found on PATH.",
    "",
    "Install options:",
    "  - Homebrew (recommended, ships a single binary):",
    "      brew install cloakward/cloak/cloak",
    "  - Platform tarball or Claude Desktop .dxt:",
    "      https://github.com/cloakward/cloak/releases",
    "  - Or install Bun and rerun:",
    "      curl -fsSL https://bun.sh/install | bash",
    "",
    "If `bun` is installed under a non-standard path, set CLOAK_BUN to its",
    "absolute path and rerun.",
    "",
  ].join("\n");
  process.stderr.write(msg);
  process.exit(127);
}

function main() {
  if (!existsSync(SERVER_ENTRY)) {
    process.stderr.write(
      `cloak-mcp: server entry not found at ${SERVER_ENTRY}\n` +
        "The package install looks corrupted; try `npm install -g @cloak-ward/mcp` again.\n",
    );
    process.exit(2);
  }

  const bun = findBun();
  if (!bun) {
    dieWithoutBun();
    return;
  }

  const args = ["run", SERVER_ENTRY, ...process.argv.slice(2)];
  const child = spawn(bun, args, {
    stdio: "inherit",
    // The MCP transport is stdio; do not let a shell wrap mangle framing.
    shell: false,
    env: process.env,
  });

  // Forward common termination signals so daemons / parent shells can
  // tear down the server cleanly. SIGKILL is uncatchable so we omit it.
  const signals = ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"];
  for (const sig of signals) {
    process.on(sig, () => {
      if (!child.killed) child.kill(sig);
    });
  }

  child.on("error", (err) => {
    process.stderr.write(`cloak-mcp: failed to spawn bun: ${err.message}\n`);
    process.exit(1);
  });

  child.on("exit", (code, signal) => {
    if (signal) {
      // Mirror the child's signal exit for shell scripts that check $?.
      process.exit(128 + (typeof signal === "string" ? 15 : 0));
    }
    process.exit(code ?? 0);
  });
}

main();
