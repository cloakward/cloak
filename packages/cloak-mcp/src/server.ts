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
import packageJson from "../package.json" with { type: "json" };
import { tools, dispatchTool } from "./tools/index.ts";
import { handshakeWithDxtFirstRun } from "./dxt-first-run.ts";
import { setSessionInitializer } from "./ipc.ts";
import { runSelfTest } from "./self-test.ts";

const VERSION = packageJson.version;

// Top-level brief handed to the client on initialize. Clients surface this to
// the model before it picks a tool, so it has to reset the default prior
// ("read the secret, then use it myself") to Cloak's model ("never read it;
// ask Cloak to make the authenticated call"). Without this, agents reach for a
// nonexistent read tool or shell out to the CLI and give up.
const SERVER_INSTRUCTIONS = [
  "Cloak is a local secrets vault. The secret values it holds must never be revealed to you or written into the conversation, and by design there is NO tool and no way to read a secret's value.",
  "",
  "To USE a secret, do not try to fetch it. Let Cloak make the authenticated request for you, and it returns the response with the secret redacted:",
  "- Calling an API that authenticates with an API key, token, bearer, or HTTP Basic credential (for example Stripe, OpenAI, GitHub, Slack): use proxy_authenticated_http_request. This is the normal path; reach for it first.",
  "- Only when an API requires request signing (AWS SigV4 or HMAC-SHA256): use sign_request.",
  "- list_secret_names and get_secret_metadata show which secrets exist (names and metadata only). query_audit reads the audit log.",
  "",
  "Do not try to obtain the raw key value. There is no MCP tool that returns a secret, and reading it out of band (shelling out to `cloak show` or `cloak run`, environment variables, or curl with the key inline) is not the supported path: `cloak show` and `cloak run` require interactive user presence and will not return a value to you here. If you find yourself wanting the key's value, use proxy_authenticated_http_request instead and let Cloak make the call.",
].join("\n");

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

  // Register the daemon handshake to run lazily on the first tool call, NOT at
  // startup. Doing it here previously blocked the MCP `initialize` response
  // behind a synchronous daemon status check, so strict clients (Codex times
  // out MCP startup after 30s) never saw the server come up. tools/list needs
  // no daemon and stays instant; the first tool call establishes the session
  // and attaches the token. The daemon's peer auth still happens at IPC connect.
  setSessionInitializer(() => handshakeWithDxtFirstRun());

  const server = new Server(
    { name: "cloak-mcp", version: VERSION },
    { capabilities: { tools: {} }, instructions: SERVER_INSTRUCTIONS },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: tools.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
      outputSchema: t.outputSchema,
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
  // Stderr only; stdout is reserved for MCP framing.
  const msg = err instanceof Error ? err.message : String(err);
  process.stderr.write(`cloak-mcp fatal: ${msg}\n`);
  process.exit(1);
});
