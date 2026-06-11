import { z } from "zod";
import { request } from "../ipc.ts";
import type { CloakTool, ToolResult } from "./types.ts";
import {
  JSON_SCHEMA_URI,
  CREDENTIAL_URL_JSON_PATTERN,
  MAX_BODY_B64_LENGTH,
  MAX_HEADER_COUNT,
  MAX_HEADER_NAME_LENGTH,
  MAX_HEADER_VALUE_LENGTH,
  MAX_URL_LENGTH,
  authHeaderNameSchema,
  base64Schema,
  headersSchema,
  httpMethodSchema,
  httpsUrlSchema,
  inputHeadersJsonSchema,
  proxyResponseOutputJsonSchema,
  proxyResponseOutputSchema,
  secretNameSchema,
} from "./validation.ts";

const argsSchema = z
  .object({
    secret_name: secretNameSchema,
    method: httpMethodSchema,
    url: httpsUrlSchema,
    headers: headersSchema.optional(),
    body_b64: base64Schema.optional(),
    auth_scheme: z.enum(["bearer", "basic", "header"]),
    header_name: authHeaderNameSchema.optional(),
  })
  .strict()
  .superRefine((args, ctx) => {
    if (args.auth_scheme === "header") {
      if (!args.header_name) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["header_name"],
          message: "header_name is required when auth_scheme is 'header'",
        });
      }
      return;
    }

    if (args.header_name) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["header_name"],
        message: "header_name is only allowed when auth_scheme is 'header'",
      });
    }
  });

const inputSchema = {
  $schema: JSON_SCHEMA_URI,
  type: "object",
  properties: {
    secret_name: { type: "string", minLength: 1, maxLength: 256, description: "Name of the stored secret to attach as auth." },
    method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"], description: "HTTP method." },
    url: {
      type: "string",
      format: "uri",
      pattern: "^https://",
      not: { pattern: CREDENTIAL_URL_JSON_PATTERN },
      maxLength: MAX_URL_LENGTH,
      description:
        "Full HTTPS request URL. Must be on the user's allowlist and must not include URL credentials or credential-shaped query parameters.",
    },
    headers: {
      ...inputHeadersJsonSchema,
      propertyNames: { ...inputHeadersJsonSchema.propertyNames, maxLength: MAX_HEADER_NAME_LENGTH },
      additionalProperties: { ...inputHeadersJsonSchema.additionalProperties, maxLength: MAX_HEADER_VALUE_LENGTH },
      maxProperties: MAX_HEADER_COUNT,
      description:
        "Optional request headers. Auth header is added by the daemon; credential-bearing input headers are rejected.",
    },
    body_b64: {
      type: "string",
      maxLength: MAX_BODY_B64_LENGTH,
      pattern: "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
      description: "Optional standard base64-encoded request body.",
    },
    auth_scheme: {
      type: "string",
      enum: ["bearer", "basic", "header"],
      description:
        "How to attach the secret: 'bearer' = Authorization: Bearer <s>; 'basic' = HTTP Basic; 'header' = custom header (provide header_name). Query-string auth is disabled.",
    },
    header_name: {
      type: "string",
      minLength: 1,
      maxLength: 128,
      pattern: "^[A-Za-z0-9!#$%&'*+\\-.^_`|~]+$",
      not: {
        pattern:
          "^(?:[Hh][Oo][Ss][Tt]|[Cc][Oo][Nn][Tt][Ee][Nn][Tt]-[Ll][Ee][Nn][Gg][Tt][Hh]|[Tt][Rr][Aa][Nn][Ss][Ff][Ee][Rr]-[Ee][Nn][Cc][Oo][Dd][Ii][Nn][Gg]|[Cc][Oo][Nn][Nn][Ee][Cc][Tt][Ii][Oo][Nn]|[Pp][Rr][Oo][Xx][Yy]-[Cc][Oo][Nn][Nn][Ee][Cc][Tt][Ii][Oo][Nn]|[Uu][Pp][Gg][Rr][Aa][Dd][Ee]|[Kk][Ee][Ee][Pp]-[Aa][Ll][Ii][Vv][Ee]|[Tt][Ee]|[Tt][Rr][Aa][Ii][Ll][Ee][Rr]|[Ee][Xx][Pp][Ee][Cc][Tt])$",
      },
      description: "Required when auth_scheme is 'header'.",
    },
  },
  required: ["secret_name", "method", "url", "auth_scheme"],
  allOf: [
    {
      if: { properties: { auth_scheme: { const: "header" } }, required: ["auth_scheme"] },
      then: { required: ["header_name"] },
    },
    {
      if: { properties: { auth_scheme: { enum: ["bearer", "basic"] } }, required: ["auth_scheme"] },
      then: { not: { required: ["header_name"] } },
    },
  ],
  additionalProperties: false,
} as const;

interface ProxyResponse {
  status: number;
  headers: Record<string, string>;
  body_b64: string;
  redacted?: boolean;
}

function isPrintableUtf8(buf: Buffer): boolean {
  // Heuristic: try utf-8 decode, allow control chars common in text (\t \n \r),
  // reject if non-printable bytes exceed 5%.
  const str = buf.toString("utf8");
  if (Buffer.byteLength(str, "utf8") !== buf.length) return false; // bad utf-8
  let bad = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if (c === 9 || c === 10 || c === 13) continue;
    if (c < 32 || c === 127) bad++;
  }
  return str.length === 0 || bad / str.length < 0.05;
}

function formatProxyResponse(r: ProxyResponse): string {
  const headerLines = Object.entries(r.headers ?? {})
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");
  let bodyText: string;
  try {
    const buf = Buffer.from(r.body_b64 ?? "", "base64");
    if (buf.length === 0) {
      bodyText = "";
    } else if (isPrintableUtf8(buf)) {
      bodyText = buf.toString("utf8");
    } else {
      bodyText = `<binary, ${buf.length} bytes>`;
    }
  } catch {
    bodyText = "<undecodable body>";
  }
  return `Status ${r.status}\n${headerLines}\n\n${bodyText}`;
}

export const proxyAuthenticatedHttpRequest: CloakTool = {
  name: "proxy_authenticated_http_request",
  description:
    "Make an authenticated HTTPS API call using a stored secret as the credential. This is the primary way to call an external API that authenticates with an API key or token (for example Stripe, OpenAI, GitHub, or Slack): the daemon attaches the named secret as a Bearer token, HTTP Basic credential, or custom header, sends the request to a host on the user's allowlist, and returns the status, redacted headers, and base64-encoded body. The secret value is never disclosed to you. Query-string auth is disabled because URLs are commonly logged.",
  inputSchema,
  outputSchema: proxyResponseOutputJsonSchema,
  async handler(rawArgs: unknown): Promise<ToolResult> {
    const parsed = argsSchema.parse(rawArgs);
    const result = proxyResponseOutputSchema.parse(await request("tool.proxy_http", parsed));
    return {
      content: [{ type: "text", text: formatProxyResponse(result) }],
      structuredContent: result,
    };
  },
};

// Exposed for unit tests.
export const _formatProxyResponse = formatProxyResponse;
