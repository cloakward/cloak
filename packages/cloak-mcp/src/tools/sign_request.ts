import { z } from "zod";
import { request } from "../ipc.ts";
import type { CloakTool, ToolResult } from "./types.ts";

const argsSchema = z
  .object({
    secret_name: z.string().min(1),
    scheme: z.enum(["aws-sigv4", "hmac-sha256"]),
    method: z.string().min(1),
    url: z.string().min(1),
    headers: z.record(z.string()).optional(),
    body_b64: z.string().optional(),
  })
  .strict();

const inputSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {
    secret_name: { type: "string", minLength: 1, description: "Name of the stored secret to use as signing key." },
    scheme: { type: "string", enum: ["aws-sigv4", "hmac-sha256"], description: "Signing scheme." },
    method: { type: "string", minLength: 1, description: "HTTP method, e.g. GET, POST." },
    url: { type: "string", minLength: 1, description: "Full request URL including query string." },
    headers: {
      type: "object",
      additionalProperties: { type: "string" },
      description: "Optional request headers (case-insensitive keys handled by daemon).",
    },
    body_b64: { type: "string", description: "Optional base64-encoded request body." },
  },
  required: ["secret_name", "scheme", "method", "url"],
  additionalProperties: false,
} as const;

export const signRequest: CloakTool = {
  name: "sign_request",
  description:
    "Compute authentication headers for an outbound HTTP request using a stored secret as the signing key. Supports AWS SigV4 and generic HMAC-SHA256. Returns only the computed headers — the underlying secret is never disclosed. Use this when an API requires request signing rather than a bearer token.",
  inputSchema,
  async handler(rawArgs: unknown): Promise<ToolResult> {
    const parsed = argsSchema.parse(rawArgs);
    const result = await request("tool.sign_request", parsed);
    return { content: [{ type: "text", text: JSON.stringify(result) }] };
  },
};
