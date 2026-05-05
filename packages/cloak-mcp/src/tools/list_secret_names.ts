import { z } from "zod";
import { request } from "../ipc.ts";
import type { CloakTool, ToolResult } from "./types.ts";

const argsSchema = z.object({}).strict();

const inputSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {},
  additionalProperties: false,
} as const;

export const listSecretNames: CloakTool = {
  name: "list_secret_names",
  description:
    "List the names and metadata of secrets stored in the local Cloak vault. Returns names, kinds, and tags only — never the secret values themselves.",
  inputSchema,
  async handler(rawArgs: unknown): Promise<ToolResult> {
    argsSchema.parse(rawArgs ?? {});
    const result = await request("vault.list", {});
    return {
      content: [{ type: "text", text: JSON.stringify(result) }],
    };
  },
};
