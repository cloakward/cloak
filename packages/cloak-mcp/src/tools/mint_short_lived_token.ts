import { z } from "zod";
import { request } from "../ipc.ts";
import { jsonToolResult, type CloakTool, type ToolResult } from "./types.ts";
import {
  JSON_SCHEMA_URI,
  MAX_SCOPE_BYTES,
  MAX_SCOPE_DEPTH,
  MAX_SCOPE_KEYS,
  MAX_TTL_SECONDS,
  mintedTokenOutputJsonSchema,
  mintedTokenOutputSchema,
  scopeJsonSchema,
  scopeSchema,
  secretNameSchema,
  ttlSecondsSchema,
} from "./validation.ts";

const argsSchema = z
  .object({
    secret_name: secretNameSchema,
    kind: z.enum(["aws-sts", "github-app", "gitlab-pat"]),
    scope: scopeSchema.optional(),
    ttl_seconds: ttlSecondsSchema.optional(),
  })
  .strict();

const inputSchema = {
  $schema: JSON_SCHEMA_URI,
  type: "object",
  properties: {
    secret_name: { type: "string", minLength: 1, maxLength: 256, description: "Name of the parent (long-lived) secret." },
    kind: {
      type: "string",
      enum: ["aws-sts", "github-app", "gitlab-pat"],
      description: "What flavor of derived token to mint.",
    },
    scope: {
      ...scopeJsonSchema,
      description: `Optional scope/claims object passed to the minting backend. Max ${MAX_SCOPE_BYTES} bytes and ${MAX_SCOPE_DEPTH} levels deep; credential-shaped fields are rejected.`,
    },
    ttl_seconds: {
      type: "integer",
      minimum: 1,
      maximum: MAX_TTL_SECONDS,
      description: "Optional requested lifetime in seconds. Daemon may cap to a policy-defined maximum.",
    },
  },
  required: ["secret_name", "kind"],
  additionalProperties: false,
} as const;

export const mintShortLivedToken: CloakTool = {
  name: "mint_short_lived_token",
  description:
    "Mint a short-lived derived token from a long-lived parent secret. AWS STS is implemented; GitHub App and GitLab PAT kinds are reserved and currently return not-supported. Returns the derived token and its expiry. The long-lived parent never leaves the daemon.",
  inputSchema,
  outputSchema: mintedTokenOutputJsonSchema,
  async handler(rawArgs: unknown): Promise<ToolResult> {
    const parsed = argsSchema.parse(rawArgs);
    const result = mintedTokenOutputSchema.parse(await request("tool.mint_token", parsed));
    return jsonToolResult(result);
  },
};
