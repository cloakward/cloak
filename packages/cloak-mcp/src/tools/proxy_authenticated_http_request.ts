import { z } from "zod";
import { request } from "../ipc.ts";
import type { CloakTool, ToolResult } from "./types.ts";
import {
  base64Schema,
  headerNameSchema,
  headersSchema,
  httpMethodSchema,
  httpsUrlSchema,
  queryNameSchema,
  secretNameSchema,
} from "./validation.ts";

const argsSchema = z
  .object({
    secret_name: secretNameSchema,
    method: httpMethodSchema,
    url: httpsUrlSchema,
    headers: headersSchema.optional(),
    body_b64: base64Schema.optional(),
    auth_scheme: z.enum(["bearer", "basic", "header", "query"]),
    header_name: headerNameSchema.optional(),
    query_name: queryNameSchema.optional(),
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
      if (args.query_name) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["query_name"],
          message: "query_name is only allowed when auth_scheme is 'query'",
        });
      }
      return;
    }

    if (args.auth_scheme === "query") {
      if (!args.query_name) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["query_name"],
          message: "query_name is required when auth_scheme is 'query'",
        });
      }
      if (args.header_name) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["header_name"],
          message: "header_name is only allowed when auth_scheme is 'header'",
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
    if (args.query_name) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["query_name"],
        message: "query_name is only allowed when auth_scheme is 'query'",
      });
    }
  });

const inputSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {
    secret_name: { type: "string", minLength: 1, maxLength: 256, description: "Name of the stored secret to attach as auth." },
    method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"], description: "HTTP method." },
    url: { type: "string", format: "uri", pattern: "^https://", description: "Full HTTPS request URL. Must be on the user's allowlist." },
    headers: {
      type: "object",
      propertyNames: { pattern: "^[A-Za-z0-9!#$%&'*+\\-.^_`|~]+$" },
      additionalProperties: { type: "string", maxLength: 8192, not: { pattern: "[\\r\\n]" } },
      description: "Optional request headers. Auth header is added by the daemon.",
    },
    body_b64: {
      type: "string",
      pattern: "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
      description: "Optional standard base64-encoded request body.",
    },
    auth_scheme: {
      type: "string",
      enum: ["bearer", "basic", "header", "query"],
      description:
        "How to attach the secret: 'bearer' = Authorization: Bearer <s>; 'basic' = HTTP Basic; 'header' = custom header (provide header_name); 'query' = URL query parameter (provide query_name).",
    },
    header_name: {
      type: "string",
      minLength: 1,
      maxLength: 128,
      pattern: "^[A-Za-z0-9!#$%&'*+\\-.^_`|~]+$",
      description: "Required when auth_scheme is 'header'.",
    },
    query_name: { type: "string", minLength: 1, maxLength: 128, description: "Required when auth_scheme is 'query'." },
  },
  required: ["secret_name", "method", "url", "auth_scheme"],
  allOf: [
    {
      if: { properties: { auth_scheme: { const: "header" } }, required: ["auth_scheme"] },
      then: { required: ["header_name"], not: { required: ["query_name"] } },
    },
    {
      if: { properties: { auth_scheme: { const: "query" } }, required: ["auth_scheme"] },
      then: { required: ["query_name"], not: { required: ["header_name"] } },
    },
    {
      if: { properties: { auth_scheme: { enum: ["bearer", "basic"] } }, required: ["auth_scheme"] },
      then: { not: { anyOf: [{ required: ["header_name"] }, { required: ["query_name"] }] } },
    },
  ],
  additionalProperties: false,
} as const;

interface ProxyResponse {
  status: number;
  headers: Record<string, string>;
  body_b64: string;
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
    "Send an HTTPS request to a host on the user's allowlist, with the named secret attached by the daemon as authentication. The request and response transit the local daemon, never this tool. Returns status, headers, and base64-encoded body. The auth header is stripped from the echoed request metadata. Use this to call APIs (GitHub, OpenAI, Stripe, etc.) without ever handling the key.",
  inputSchema,
  async handler(rawArgs: unknown): Promise<ToolResult> {
    const parsed = argsSchema.parse(rawArgs);
    const result = (await request("tool.proxy_http", parsed)) as ProxyResponse;
    return {
      content: [{ type: "text", text: formatProxyResponse(result) }],
    };
  },
};

// Exposed for unit tests.
export const _formatProxyResponse = formatProxyResponse;
