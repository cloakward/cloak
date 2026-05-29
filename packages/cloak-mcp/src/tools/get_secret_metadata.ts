import { z } from "zod";
import { request } from "../ipc.ts";
import { jsonToolResult, type CloakTool, type ToolResult } from "./types.ts";
import {
  JSON_SCHEMA_URI,
  secretMetadataJsonSchema,
  secretMetadataSchema,
  secretNameSchema,
} from "./validation.ts";

const argsSchema = z
  .object({
    name: secretNameSchema,
  })
  .strict();

const inputSchema = {
  $schema: JSON_SCHEMA_URI,
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
  outputSchema: { $schema: JSON_SCHEMA_URI, ...secretMetadataJsonSchema },
  async handler(rawArgs: unknown): Promise<ToolResult> {
    const parsed = argsSchema.parse(rawArgs);
    const result = await request("vault.get_metadata", parsed);
    const metadata = secretMetadataSchema.parse(result);
    return jsonToolResult(metadata);
  },
};
