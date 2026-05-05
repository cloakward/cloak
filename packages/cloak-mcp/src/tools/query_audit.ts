import { z } from "zod";
import { request } from "../ipc.ts";
import type { CloakTool, ToolResult } from "./types.ts";

const argsSchema = z
  .object({
    since: z.string().optional(),
    until: z.string().optional(),
    tool: z.string().optional(),
    secret: z.string().optional(),
    result: z.string().optional(),
    limit: z.number().int().positive().optional(),
  })
  .strict();

const inputSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {
    since: { type: "string", description: "Inclusive lower bound (RFC3339 timestamp) for audit entries." },
    until: { type: "string", description: "Exclusive upper bound (RFC3339 timestamp) for audit entries." },
    tool: { type: "string", description: "Filter by tool name (e.g. 'sign_request')." },
    secret: { type: "string", description: "Filter by secret name." },
    result: { type: "string", description: "Filter by result tag (e.g. 'ok', 'denied', 'error')." },
    limit: { type: "integer", minimum: 1, description: "Maximum number of entries to return." },
  },
  required: [],
  additionalProperties: false,
} as const;

export const queryAudit: CloakTool = {
  name: "query_audit",
  description:
    "Query the local Cloak audit log of privileged operations. Filterable by time range, tool name, secret name, and result. Returns audit entries — never secret values.",
  inputSchema,
  async handler(rawArgs: unknown): Promise<ToolResult> {
    const parsed = argsSchema.parse(rawArgs ?? {});
    const result = await request("tool.query_audit", parsed);
    return { content: [{ type: "text", text: JSON.stringify(result) }] };
  },
};
