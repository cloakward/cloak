#!/usr/bin/env node
// CI gate: forbid direct HTTP/networking imports, fetch/WebSocket calls, and
// spawns of network CLIs in src/. Cloak's invariant is that the MCP shim
// performs ZERO outbound network I/O of its own — all egress originates from
// the Rust daemon. `node:net` is the only permitted network primitive (the
// local UDS in ipc.ts); `node:child_process` is permitted only to launch the
// trusted `cloak` CLI.
//
// This is a regression guard, NOT a sandbox: it stops outbound networking
// from being reintroduced by accident during a refactor. A determined author
// can still bypass a static scan (aliased/dynamic imports, base64-eval, …);
// the real boundary is the daemon's peer-auth and the published binary being
// built solely from src/. Keep that boundary — don't treat this as airtight.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const ROOT = join(__dirname, "..");
const SRC = join(ROOT, "src");

// Banned bare-module identifiers (matched as imported module specifiers).
// NOTE: `net`/`node:net` and `child_process`/`node:child_process` are
// deliberately NOT banned — they are the permitted UDS + trusted-CLI paths.
const BANNED_MODULES = [
  "http",
  "https",
  "node:http",
  "node:https",
  "http2",
  "node:http2",
  "dns",
  "node:dns",
  "node:dns/promises",
  "dgram",
  "node:dgram",
  "tls",
  "node:tls",
  "axios",
  "undici",
  "node-fetch",
  "got",
  "ws",
];

// Patterns:
//  - import ... from "<banned>"
//  - require("<banned>")
const importPatterns = BANNED_MODULES.map(
  (m) =>
    new RegExp(
      String.raw`(?:from\s*['"]${escapeRegex(m)}['"]|require\(\s*['"]${escapeRegex(m)}['"]\s*\)|import\(\s*['"]${escapeRegex(m)}['"]\s*\))`,
    ),
);

// Banned call / construction patterns (comments already stripped). Covers
// bare `fetch(`, indirect `globalThis|window|self|global.fetch(`, bracket
// access `global["fetch"]`, and `new WebSocket(` / `new EventSource(`.
const bannedCallPatterns = [
  { re: /(?<![A-Za-z0-9_$.])fetch\s*\(/, label: "fetch() call" },
  { re: /(?:globalThis|window|self|global)\s*\.\s*fetch\b/, label: "indirect fetch reference" },
  { re: /(?:globalThis|window|self|global)\s*\[\s*['"]fetch['"]\s*\]/, label: "indirect fetch reference" },
  { re: /\bnew\s+WebSocket\b/, label: "WebSocket" },
  { re: /\bnew\s+EventSource\b/, label: "EventSource" },
];

// Heuristic: flag spawning a known network CLI by literal name. Won't catch
// a variable-built command, but stops the obvious `spawnSync("curl", …)`
// exfil path that the module bans miss (child_process is allowed only to
// launch the trusted cloak CLI, which is referenced by a path variable).
const bannedSpawnTarget = /['"`](?:curl|wget|nc|ncat|socat|telnet)['"`]/;

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function stripComments(line) {
  // Strip // comments. Block comments handled crudely below in caller.
  const idx = line.indexOf("//");
  if (idx >= 0) return line.slice(0, idx);
  return line;
}

function* walkTs(dir) {
  for (const ent of readdirSync(dir)) {
    const p = join(dir, ent);
    const s = statSync(p);
    if (s.isDirectory()) {
      yield* walkTs(p);
    } else if (s.isFile() && p.endsWith(".ts")) {
      yield p;
    }
  }
}

let offenders = [];

for (const file of walkTs(SRC)) {
  const content = readFileSync(file, "utf8");
  // Crude block-comment removal (handles /* ... */ on same line or spanning).
  const noBlock = content.replace(/\/\*[\s\S]*?\*\//g, "");
  const lines = noBlock.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const line = stripComments(raw);
    if (!line.trim()) continue;
    for (const pat of importPatterns) {
      if (pat.test(line)) {
        offenders.push(`${relative(ROOT, file)}:${i + 1}: banned import: ${line.trim()}`);
      }
    }
    for (const { re, label } of bannedCallPatterns) {
      if (re.test(line)) {
        offenders.push(`${relative(ROOT, file)}:${i + 1}: banned ${label}: ${line.trim()}`);
      }
    }
    if (bannedSpawnTarget.test(line)) {
      offenders.push(`${relative(ROOT, file)}:${i + 1}: banned network CLI spawn: ${line.trim()}`);
    }
  }
}

if (offenders.length > 0) {
  console.error("cloak-mcp: outbound HTTP gate FAILED");
  for (const o of offenders) console.error("  " + o);
  process.exit(1);
}

console.log(
  "cloak-mcp: outbound network gate ok (no banned imports, fetch/WebSocket calls, or network-CLI spawns in src/)",
);
