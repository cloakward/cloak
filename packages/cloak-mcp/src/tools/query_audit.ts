import { z } from "zod";
import { request } from "../ipc.ts";
import type { CloakTool, ToolResult } from "./types.ts";
import { resultLimitSchema, rfc3339ishSchema, secretNameSchema } from "./validation.ts";

const argsSchema = z
  .object({
    since: rfc3339ishSchema.optional(),
    until: rfc3339ishSchema.optional(),
    tool: z.string().min(1).max(128).optional(),
    secret: secretNameSchema.optional(),
    result: z.string().min(1).max(64).optional(),
    limit: resultLimitSchema.optional(),
  })
  .strict();

const inputSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {
    since: {
      type: "string",
      format: "date-time",
      pattern: "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,9})?(?:Z|[+-]\\d{2}:\\d{2})$",
      description: "Inclusive lower bound (RFC3339 timestamp) for audit entries.",
    },
    until: {
      type: "string",
      format: "date-time",
      pattern: "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,9})?(?:Z|[+-]\\d{2}:\\d{2})$",
      description: "Exclusive upper bound (RFC3339 timestamp) for audit entries.",
    },
    tool: { type: "string", minLength: 1, maxLength: 128, description: "Filter by tool name (e.g. 'sign_request')." },
    secret: { type: "string", minLength: 1, maxLength: 256, description: "Filter by secret name." },
    result: { type: "string", minLength: 1, maxLength: 64, description: "Filter by result tag (e.g. 'ok', 'denied', 'error')." },
    limit: { type: "integer", minimum: 1, maximum: 1000, description: "Maximum number of entries to return." },
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
