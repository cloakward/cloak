import { z } from "zod";
import { request } from "../ipc.ts";
import { jsonToolResult, type CloakTool, type ToolResult } from "./types.ts";
import { JSON_SCHEMA_URI, secretListJsonSchema, secretListSchema } from "./validation.ts";

const argsSchema = z.object({}).strict();

const inputSchema = {
  $schema: JSON_SCHEMA_URI,
  type: "object",
  properties: {},
  additionalProperties: false,
} as const;

export const listSecretNames: CloakTool = {
  name: "list_secret_names",
  description:
    "List the names and metadata of secrets stored in the local Cloak vault. Returns names, kinds, and tags only — never the secret values themselves.",
  inputSchema,
  outputSchema: secretListJsonSchema,
  async handler(rawArgs: unknown): Promise<ToolResult> {
    argsSchema.parse(rawArgs ?? {});
    const result = await request("vault.list", {});
    const parsed = secretListSchema.parse(result);
    return jsonToolResult(parsed);
  },
};
