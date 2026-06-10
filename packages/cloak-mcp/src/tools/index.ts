import type { CloakTool, ToolResult } from "./types.ts";
import { listSecretNames } from "./list_secret_names.ts";
import { getSecretMetadata } from "./get_secret_metadata.ts";
import { signRequest } from "./sign_request.ts";
import { proxyAuthenticatedHttpRequest } from "./proxy_authenticated_http_request.ts";
import { mintShortLivedToken } from "./mint_short_lived_token.ts";
import { queryAudit } from "./query_audit.ts";
import { redactText } from "./validation.ts";

export const tools: ReadonlyArray<CloakTool> = [
  listSecretNames,
  getSecretMetadata,
  signRequest,
  proxyAuthenticatedHttpRequest,
  mintShortLivedToken,
  queryAudit,
];

const byName: Map<string, CloakTool> = new Map(tools.map((t) => [t.name, t]));

export async function dispatchTool(name: string, args: unknown): Promise<ToolResult> {
  const tool = byName.get(name);
  if (!tool) {
    return {
      content: [{ type: "text", text: `error: unknown tool '${name}'` }],
      isError: true,
    };
  }
  try {
    return await tool.handler(args);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    // `redactText` is a best-effort, shape-based net (see its JSDoc). The
    // real guarantee is that the daemon never puts a stored secret into an
    // error message; this just hardens against accidental leakage.
    return {
      content: [{ type: "text", text: `error: ${redactText(msg)}` }],
      isError: true,
    };
  }
}

export type { CloakTool, ToolResult };
