import { z } from "zod";
import { request } from "../ipc.ts";
import { jsonToolResult, type CloakTool, type ToolResult } from "./types.ts";
import {
  JSON_SCHEMA_URI,
  CREDENTIAL_URL_JSON_PATTERN,
  MAX_BODY_B64_LENGTH,
  MAX_HEADER_COUNT,
  MAX_HEADER_NAME_LENGTH,
  MAX_HEADER_VALUE_LENGTH,
  MAX_URL_LENGTH,
  base64Schema,
  headersSchema,
  httpMethodSchema,
  httpUrlSchema,
  inputHeadersJsonSchema,
  signRequestOutputJsonSchema,
  signRequestOutputSchema,
  secretNameSchema,
} from "./validation.ts";

const argsSchema = z
  .object({
    secret_name: secretNameSchema,
    scheme: z.enum(["aws-sigv4", "hmac-sha256"]),
    method: httpMethodSchema,
    url: httpUrlSchema,
    headers: headersSchema.optional(),
    body_b64: base64Schema.optional(),
    aws_region: z.string().min(1).max(128).regex(/^[A-Za-z0-9-]+$/).optional(),
    aws_service: z.string().min(1).max(128).regex(/^[A-Za-z0-9-]+$/).optional(),
  })
  .strict();

const inputSchema = {
  $schema: JSON_SCHEMA_URI,
  type: "object",
  properties: {
    secret_name: { type: "string", minLength: 1, maxLength: 256, description: "Name of the stored secret to use as signing key." },
    scheme: { type: "string", enum: ["aws-sigv4", "hmac-sha256"], description: "Signing scheme." },
    method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"], description: "HTTP method." },
    url: {
      type: "string",
      format: "uri",
      pattern: "^https?://",
      not: { pattern: CREDENTIAL_URL_JSON_PATTERN },
      maxLength: MAX_URL_LENGTH,
      description:
        "Full http(s) request URL including query string. Must not include URL credentials or credential-shaped query parameters.",
    },
    headers: {
      ...inputHeadersJsonSchema,
      propertyNames: { ...inputHeadersJsonSchema.propertyNames, maxLength: MAX_HEADER_NAME_LENGTH },
      additionalProperties: { ...inputHeadersJsonSchema.additionalProperties, maxLength: MAX_HEADER_VALUE_LENGTH },
      maxProperties: MAX_HEADER_COUNT,
      description:
        "Optional request headers (case-insensitive keys handled by daemon). Credential-bearing headers are rejected.",
    },
    body_b64: {
      type: "string",
      maxLength: MAX_BODY_B64_LENGTH,
      pattern: "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
      description: "Optional standard base64-encoded request body.",
    },
    aws_region: {
      type: "string",
      minLength: 1,
      maxLength: 128,
      pattern: "^[A-Za-z0-9-]+$",
      description: "AWS SigV4 region, for example us-east-1. Used only when scheme is aws-sigv4.",
    },
    aws_service: {
      type: "string",
      minLength: 1,
      maxLength: 128,
      pattern: "^[A-Za-z0-9-]+$",
      description: "AWS SigV4 service, for example execute-api or s3. Used only when scheme is aws-sigv4.",
    },
  },
  required: ["secret_name", "scheme", "method", "url"],
  additionalProperties: false,
} as const;

export const signRequest: CloakTool = {
  name: "sign_request",
  description:
    "Compute authentication headers for an outbound HTTP request using a stored secret as the signing key. Supports AWS SigV4 and generic HMAC-SHA256. Returns only the computed headers — the underlying secret is never disclosed. Use this when an API requires request signing rather than a bearer token.",
  inputSchema,
  outputSchema: signRequestOutputJsonSchema,
  async handler(rawArgs: unknown): Promise<ToolResult> {
    const parsed = argsSchema.parse(rawArgs);
    const result = await request("tool.sign_request", parsed);
    const output = signRequestOutputSchema.parse(result);
    return jsonToolResult(output);
  },
};
