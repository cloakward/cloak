import { z } from "zod";
import { request } from "../ipc.ts";
import { jsonToolResult, type CloakTool, type ToolResult } from "./types.ts";
import {
  JSON_SCHEMA_URI,
  auditQueryOutputJsonSchema,
  auditQueryOutputSchema,
  resultLimitSchema,
  rfc3339ishSchema,
  secretNameSchema,
} from "./validation.ts";

const noControl = (value: string): boolean => !/[\u0000-\u001f\u007f]/.test(value);

const argsSchema = z
  .object({
    since: rfc3339ishSchema.optional(),
    until: rfc3339ishSchema.optional(),
    tool: z.string().min(1).max(128).refine(noControl, "must not contain control characters").optional(),
    secret: secretNameSchema.optional(),
    result: z.enum(["started", "ok", "denied", "error"]).optional(),
    limit: resultLimitSchema.optional(),
  })
  .strict();

const inputSchema = {
  $schema: JSON_SCHEMA_URI,
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
    result: { type: "string", enum: ["started", "ok", "denied", "error"], description: "Filter by result tag." },
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
  outputSchema: auditQueryOutputJsonSchema,
  async handler(rawArgs: unknown): Promise<ToolResult> {
    const parsed = argsSchema.parse(rawArgs ?? {});
    const result = auditQueryOutputSchema.parse(await request("tool.query_audit", parsed));
    return jsonToolResult(result);
  },
};
