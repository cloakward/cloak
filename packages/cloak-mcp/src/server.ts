// Cloak MCP server (model surface).
//
// Critical invariant: this package never sees plaintext secrets and never
// makes any outbound HTTP request. It is a pure translator between MCP tool
// calls and IPC requests to the local cloakd daemon.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import { tools, dispatchTool } from "./tools/index.ts";
import { handshake } from "./ipc.ts";
import { runSelfTest } from "./self-test.ts";

const VERSION = "0.9.0-rc1";

function printVersion(): void {
  process.stdout.write(`cloak-mcp ${VERSION}\n`);
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);

  if (argv.includes("--version") || argv.includes("-v")) {
    printVersion();
    process.exit(0);
  }
  if (argv.includes("--self-test")) {
    try {
      await runSelfTest();
      process.exit(0);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`self-test failed: ${msg}\n`);
      process.exit(2);
    }
  }

  // The daemon's peer auth happens at IPC connect; we handshake to obtain
  // a session token that gets attached to subsequent requests.
  await handshake();

  const server = new Server(
    { name: "cloak-mcp", version: VERSION },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: tools.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
    })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req): Promise<CallToolResult> => {
    const out = await dispatchTool(req.params.name, req.params.arguments ?? {});
    return out as CallToolResult;
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err: unknown) => {
  // Stderr only — stdout is reserved for MCP framing.
  const msg = err instanceof Error ? err.message : String(err);
  process.stderr.write(`cloak-mcp fatal: ${msg}\n`);
  process.exit(1);
});
