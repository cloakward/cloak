#!/usr/bin/env node
// Fail-closed npm launcher.
//
// Production cloakd authenticates MCP peers by the native `cloak-mcp`
// executable identity. The old npm launcher ran the TypeScript server under
// `bun`, which cannot satisfy that peer-auth policy. npm publishing is paused
// until this package ships audited native binaries per supported platform.

import process from "node:process";

process.stderr.write(
  [
    "cloak-mcp: npm distribution is paused for production installs.",
    "",
    "Use one of the verified native install paths instead:",
    "  - brew install cloakward/cloak/cloak",
    "  - GitHub release tarballs",
    "  - signed Cloak-*.dxt assets for Claude Desktop",
    "",
    "Reason: production cloakd trusts native cloak-mcp binaries, not a bun",
    "interpreter process launched from npm.",
    "",
  ].join("\n"),
);
process.exit(1);
