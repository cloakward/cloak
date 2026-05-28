import { z } from "zod";
import { request } from "../ipc.ts";
import type { CloakTool, ToolResult } from "./types.ts";
import { secretMetadataSchema, secretNameSchema } from "./validation.ts";

const argsSchema = z
  .object({
    name: secretNameSchema,
  })
  .strict();

const inputSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {
    name: { type: "string", minLength: 1, maxLength: 256, description: "The secret name." },
  },
  required: ["name"],
  additionalProperties: false,
} as const;

export const getSecretMetadata: CloakTool = {
  name: "get_secret_metadata",
  description:
    "Return metadata about a single named secret (kind, tags, created/updated timestamps, version). Never returns the secret value.",
  inputSchema,
  async handler(rawArgs: unknown): Promise<ToolResult> {
    const parsed = argsSchema.parse(rawArgs);
    const result = await request("vault.get_metadata", parsed);
    const metadata = secretMetadataSchema.parse(result);
    return { content: [{ type: "text", text: JSON.stringify(metadata) }] };
  },
};
