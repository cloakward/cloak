#!/usr/bin/env node
// CI gate: forbid any direct HTTP/networking imports or fetch calls in src/.
// Cloak's invariant is that the MCP shim performs ZERO outbound HTTP — all
// network egress originates from the Rust daemon. This script enforces that.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const ROOT = join(__dirname, "..");
const SRC = join(ROOT, "src");

// Banned bare-module identifiers (matched as imported module specifiers).
const BANNED_MODULES = [
  "http",
  "https",
  "node:http",
  "node:https",
  "axios",
  "undici",
  "node-fetch",
  "got",
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

// Match `fetch(` as a global call. Allow comments to mention fetch.
// Detect bare `fetch(` not preceded by an identifier char or dot.
const fetchPattern = /(?<![A-Za-z0-9_$.])fetch\s*\(/;

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
    if (fetchPattern.test(line)) {
      offenders.push(`${relative(ROOT, file)}:${i + 1}: banned fetch() call: ${line.trim()}`);
    }
  }
}

if (offenders.length > 0) {
  console.error("cloak-mcp: outbound HTTP gate FAILED");
  for (const o of offenders) console.error("  " + o);
  process.exit(1);
}

console.log("cloak-mcp: outbound HTTP gate ok (no banned imports or fetch calls in src/)");
