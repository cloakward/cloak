# Cloak.dxt — Claude Desktop Extension

Drag-and-drop install of the `cloak-mcp` shim for Claude Desktop. Zero terminal commands for the install step.

## Layout

```
packaging/cloak-dxt/
├── manifest.json                # .dxt / .mcpb manifest (mcpb_version 0.1)
├── server/
│   ├── first-run.js             # native-dialog setup dispatcher
│   └── binaries/
│       └── cloak-mcp            # bundled per-platform binary (build artifact)
└── README.md                    # this file
```

`scripts/build-dxt.sh` zips this directory into `Cloak-<version>-<platform>.dxt`. The release workflow builds one `.dxt` per platform matrix row, embedding the `cloak-mcp` binary built from `packages/cloak-mcp` (`bun build src/server.ts --compile`).

## Requirements

- The `cloak` CLI must be on `PATH`. The .dxt bundles `cloak-mcp` only — `cloak` and `cloakd` ship via Homebrew / `.deb` / install script.
- On first activation, `first-run.js` invokes `cloak setup --from-dxt`, which drives biometric / passphrase prompts via the OS-native dialog APIs. The .dxt does NOT bypass any prompt.

Windows is deferred to v1.0.1.
