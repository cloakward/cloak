import { z } from "zod";
import { request } from "../ipc.ts";
import type { CloakTool, ToolResult } from "./types.ts";

const argsSchema = z
  .object({
    secret_name: z.string().min(1),
    kind: z.enum(["aws-sts", "github-app", "gitlab-pat"]),
    scope: z.record(z.unknown()).optional(),
    ttl_seconds: z.number().int().positive().optional(),
  })
  .strict();

const inputSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {
    secret_name: { type: "string", minLength: 1, description: "Name of the parent (long-lived) secret." },
    kind: {
      type: "string",
      enum: ["aws-sts", "github-app", "gitlab-pat"],
      description: "What flavor of derived token to mint.",
    },
    scope: {
      type: "object",
      description: "Optional scope/claims object passed to the minting backend (e.g. STS RoleArn, GitHub repo set).",
      additionalProperties: true,
    },
    ttl_seconds: {
      type: "integer",
      minimum: 1,
      description: "Optional requested lifetime in seconds. Daemon may cap to a policy-defined maximum.",
    },
  },
  required: ["secret_name", "kind"],
  additionalProperties: false,
} as const;

export const mintShortLivedToken: CloakTool = {
  name: "mint_short_lived_token",
  description:
    "Mint a short-lived derived token from a long-lived parent secret. Examples: STS session credentials from an AWS access key, an installation token from a GitHub App private key, a scoped PAT from a parent PAT. Returns the derived token and its expiry. The long-lived parent never leaves the daemon.",
  inputSchema,
  async handler(rawArgs: unknown): Promise<ToolResult> {
    const parsed = argsSchema.parse(rawArgs);
    const result = await request("tool.mint_token", parsed);
    return { content: [{ type: "text", text: JSON.stringify(result) }] };
  },
};
