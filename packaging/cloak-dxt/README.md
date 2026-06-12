# Cloak.dxt - Claude Desktop Extension

Drag-and-drop install of the `cloak-mcp` shim for Claude Desktop. Zero terminal commands for the install step.

## Layout

```
packaging/cloak-dxt/
├── manifest.json                # .dxt / .mcpb manifest (manifest_version 0.3)
├── server/
│   ├── first-run.js             # native-dialog setup dispatcher
│   └── binaries/
│       └── cloak-mcp            # bundled per-platform binary (build artifact)
└── README.md                    # this file
```

`scripts/build-dxt.sh` zips this directory into `Cloak-<version>-<platform>.dxt`. The release workflow builds Claude Desktop `.dxt` packages for `macos-arm64` and `macos-x64`, embedding the `cloak-mcp` binary built from `packages/cloak-mcp` (`bun build src/server.ts --compile`). Linux release tarballs still ship the CLI and daemon, and Linux x64 glibc tarballs include the native `cloak-mcp` binary, but Linux is not packaged as a Claude Desktop extension because Claude Desktop's MCPB/DXT install surface is macOS/Windows-only.

## Requirements

- The `cloak` CLI must be on `PATH` or in a trusted standard install path. The .dxt bundles `cloak-mcp` only; `cloak` and `cloakd` ship via Homebrew or the platform tarballs.
- On first activation, `first-run.js` shows terminal setup guidance when setup is required. It does not run `cloak setup` from inside Claude Desktop because the one-time recovery seed must be displayed and verified in a terminal. After setup, run `cloak daemon start` and `cloak unlock`, then restart Claude Desktop.

Windows DXT packaging is deferred until the Windows CLI/daemon release work lands.
