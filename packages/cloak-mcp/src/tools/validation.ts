import { z } from "zod";

const RFC3339ISH_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const BASE64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const HEADER_NAME_RE = /^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/;
const CONTROL_RE = /[\u0000-\u001f\u007f]/;
const HEX64_RE = /^[a-f0-9]{64}$/;
const REQUEST_CONTROL_HEADERS = new Set([
  "host",
  "content-length",
  "transfer-encoding",
  "connection",
  "proxy-connection",
  "upgrade",
  "keep-alive",
  "te",
  "trailer",
  "expect",
]);

export const MAX_URL_LENGTH = 4096;
export const MAX_HEADER_COUNT = 64;
export const MAX_HEADER_NAME_LENGTH = 128;
export const MAX_HEADER_VALUE_LENGTH = 4096;
export const MAX_HEADER_TOTAL_BYTES = 32 * 1024;
export const MAX_BODY_BYTES = 1024 * 1024;
export const MAX_BODY_B64_LENGTH = Math.ceil(MAX_BODY_BYTES / 3) * 4;
export const MAX_SCOPE_BYTES = 8192;
export const MAX_SCOPE_DEPTH = 4;
export const MAX_SCOPE_KEYS = 64;
export const MAX_SCOPE_ARRAY_ITEMS = 64;
export const MAX_SCOPE_STRING_LENGTH = 1024;
export const MAX_TTL_SECONDS = 3600;
export const MAX_DERIVED_TOKEN_LENGTH = 16 * 1024;
export const MAX_PROXY_RESPONSE_BODY_B64_LENGTH = MAX_BODY_B64_LENGTH;

export const JSON_SCHEMA_URI = "https://json-schema.org/draft/2020-12/schema";

const SENSITIVE_FIELD_JSON_PATTERN = [
  "(?:^|[_-])(?:[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]|[Aa][Cc][Cc][Ee][Ss][Ss][_-]?[Tt][Oo][Kk][Ee][Nn]|[Aa][Uu][Tt][Hh](?:[Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn])?|[Bb][Ee][Aa][Rr][Ee][Rr]|[Cc][Ll][Ii][Ee][Nn][Tt][_-]?[Ss][Ee][Cc][Rr][Ee][Tt]|[Cc][Oo][Oo][Kk][Ii][Ee]|[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll]|[Pp][Aa][Ss][Ss](?:[Ww][Oo][Rr][Dd])?|[Pp][Rr][Ii][Vv][Aa][Tt][Ee][_-]?[Kk][Ee][Yy]|[Rr][Ee][Ff][Rr][Ee][Ss][Hh][_-]?[Tt][Oo][Kk][Ee][Nn]|[Ss][Ee][Cc][Rr][Ee][Tt](?:[_-]?[A-Za-z0-9]+)*|[Ss][Ee][Ss][Ss][Ii][Oo][Nn][_-]?[Tt][Oo][Kk][Ee][Nn]|[Tt][Oo][Kk][Ee][Nn])(?:$|[_-])",
  "^(?:[Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn]|[Cc][Oo][Oo][Kk][Ii][Ee]|[Pp][Rr][Oo][Xx][Yy]-[Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn]|[Ss][Ee][Tt]-[Cc][Oo][Oo][Kk][Ii][Ee]|[Xx]-[Aa][Pp][Ii]-[Kk][Ee][Yy]|[Aa][Pp][Ii]-[Kk][Ee][Yy]|[Xx]-[Aa][Uu][Tt][Hh]-[Tt][Oo][Kk][Ee][Nn]|[Xx]-[Aa][Cc][Cc][Ee][Ss][Ss]-[Tt][Oo][Kk][Ee][Nn])$",
  "(?:[Aa][Pp][Ii][Kk][Ee][Yy]|[Aa][Cc][Cc][Ee][Ss][Ss][Tt][Oo][Kk][Ee][Nn]|[Cc][Ll][Ii][Ee][Nn][Tt][Ss][Ee][Cc][Rr][Ee][Tt]|[Pp][Rr][Ii][Vv][Aa][Tt][Ee][Kk][Ee][Yy]|[Rr][Ee][Ff][Rr][Ee][Ss][Hh][Tt][Oo][Kk][Ee][Nn]|[Ss][Ee][Ss][Ss][Ii][Oo][Nn][Tt][Oo][Kk][Ee][Nn])",
].join("|");
const CONTROL_JSON_PATTERN = "[\\u0000-\\u001f\\u007f]";
export const CREDENTIAL_URL_JSON_PATTERN =
  "://[^/?#]*@|[?&][^=&#]*(?:[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]|[Aa][Pp][Ii][Kk][Ee][Yy]|[Aa][Cc][Cc][Ee][Ss][Ss][_-]?[Tt][Oo][Kk][Ee][Nn]|[Aa][Cc][Cc][Ee][Ss][Ss][Tt][Oo][Kk][Ee][Nn]|[Cc][Ll][Ii][Ee][Nn][Tt][_-]?[Ss][Ee][Cc][Rr][Ee][Tt]|[Cc][Ll][Ii][Ee][Nn][Tt][Ss][Ee][Cc][Rr][Ee][Tt]|[Pp][Rr][Ii][Vv][Aa][Tt][Ee][_-]?[Kk][Ee][Yy]|[Pp][Rr][Ii][Vv][Aa][Tt][Ee][Kk][Ee][Yy]|[Rr][Ee][Ff][Rr][Ee][Ss][Hh][_-]?[Tt][Oo][Kk][Ee][Nn]|[Rr][Ee][Ff][Rr][Ee][Ss][Hh][Tt][Oo][Kk][Ee][Nn]|[Ss][Ee][Ss][Ss][Ii][Oo][Nn][_-]?[Tt][Oo][Kk][Ee][Nn]|[Ss][Ee][Ss][Ss][Ii][Oo][Nn][Tt][Oo][Kk][Ee][Nn]|[Aa][Uu][Tt][Hh](?:[Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn])?|[Bb][Ee][Aa][Rr][Ee][Rr]|[Cc][Oo][Oo][Kk][Ii][Ee]|[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll]|[Pp][Aa][Ss][Ss](?:[Ww][Oo][Rr][Dd])?|[Ss][Ee][Cc][Rr][Ee][Tt]|[Tt][Oo][Kk][Ee][Nn])(?:=|&|#|$)";
const SENSITIVE_SINGLE_PARTS = new Set([
  "auth",
  "authorization",
  "bearer",
  "cookie",
  "credential",
  "password",
  "passwd",
  "secret",
  "token",
]);
const SENSITIVE_PART_PAIRS = new Set([
  "api:key",
  "access:token",
  "client:secret",
  "private:key",
  "refresh:token",
  "session:token",
]);

function noControl(value: string): boolean {
  return !CONTROL_RE.test(value);
}

function jsonByteLength(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value), "utf8");
}

function decodedBase64Length(value: string): number {
  if (value.length === 0) return 0;
  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  return Math.floor((value.length / 4) * 3) - padding;
}

function headerTotalBytes(headers: Record<string, string>): number {
  return Object.entries(headers).reduce(
    (total, [name, value]) => total + Buffer.byteLength(name, "utf8") + Buffer.byteLength(value, "utf8"),
    0,
  );
}

export function isCredentialHeaderName(name: string): boolean {
  return isCredentialFieldName(name);
}

export function isRequestControlHeaderName(name: string): boolean {
  return REQUEST_CONTROL_HEADERS.has(name.toLowerCase());
}

export function isCredentialFieldName(name: string): boolean {
  const normalized = name
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^A-Za-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .toLowerCase();
  if (normalized.length === 0) return false;

  const compact = normalized.replace(/_/g, "");
  if (
    ["apikey", "accesstoken", "clientsecret", "privatekey", "refreshtoken", "sessiontoken"].some(
      (needle) => compact.includes(needle),
    )
  ) {
    return true;
  }

  const parts = normalized.split("_").filter(Boolean);
  for (const part of parts) {
    if (SENSITIVE_SINGLE_PARTS.has(part)) return true;
  }
  for (let i = 0; i + 1 < parts.length; i++) {
    if (SENSITIVE_PART_PAIRS.has(`${parts[i]}:${parts[i + 1]}`)) return true;
  }
  return false;
}

function isCredentialFreeUrl(value: string): boolean {
  try {
    const url = new URL(value);
    if (url.username || url.password) return false;
    for (const [name] of url.searchParams) {
      if (isCredentialFieldName(name)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

function validateHeaderEnvelope(headers: Record<string, string>, ctx: z.RefinementCtx): void {
  const names = Object.keys(headers);
  if (names.length > MAX_HEADER_COUNT) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: `must include at most ${MAX_HEADER_COUNT} headers`,
    });
  }
  if (headerTotalBytes(headers) > MAX_HEADER_TOTAL_BYTES) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: `headers must be at most ${MAX_HEADER_TOTAL_BYTES} bytes total`,
    });
  }
}

function validateScopeValue(
  value: unknown,
  ctx: z.RefinementCtx,
  path: Array<string | number>,
  state: { keys: number },
): void {
  if (path.length > MAX_SCOPE_DEPTH) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path,
      message: `scope must be at most ${MAX_SCOPE_DEPTH} levels deep`,
    });
    return;
  }

  if (typeof value === "string") {
    if (value.length > MAX_SCOPE_STRING_LENGTH) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path,
        message: `scope strings must be at most ${MAX_SCOPE_STRING_LENGTH} characters`,
      });
    }
    if (!noControl(value)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path,
        message: "scope strings must not contain control characters",
      });
    }
    return;
  }

  if (Array.isArray(value)) {
    if (value.length > MAX_SCOPE_ARRAY_ITEMS) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path,
        message: `scope arrays must contain at most ${MAX_SCOPE_ARRAY_ITEMS} items`,
      });
    }
    value.forEach((item, index) => validateScopeValue(item, ctx, [...path, index], state));
    return;
  }

  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      state.keys++;
      if (state.keys > MAX_SCOPE_KEYS) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path,
          message: `scope must contain at most ${MAX_SCOPE_KEYS} object keys`,
        });
        return;
      }
      if (key.length > 128 || !noControl(key)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [...path, key],
          message: "scope keys must be printable strings of at most 128 characters",
        });
      }
      if (isCredentialFieldName(key)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [...path, key],
          message: "scope must not include credential-shaped fields",
        });
      }
      validateScopeValue(child, ctx, [...path, key], state);
    }
  }
}

/**
 * Best-effort scrub of credential-shaped substrings (key:value / key=value
 * pairs with credential-like keys, Authorization/Bearer/Basic headers, and
 * JWTs) from a string before it is surfaced to the model.
 *
 * This is defense-in-depth, NOT a guarantee. It matches *shapes*, not
 * entropy: a raw secret embedded free-form in prose (e.g. "the key sk_live_…
 * was rejected") would pass through unchanged. The actual guarantee that a
 * stored secret never reaches the model lives in the daemon, which never
 * places secret values into error messages or tool results. Treat this as a
 * second net for daemon/error text, not the primary boundary.
 */
export function redactText(text: string): string {
  return text
    .replace(
      /(["'])([^"'\r\n\\]{1,128})\1(\s*[:=]\s*)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')/g,
      (match: string, keyQuote: string, key: string, separator: string, value: string) =>
        isCredentialFieldName(key)
          ? `${keyQuote}${key}${keyQuote}${separator}${value[0]}[redacted]${value[0]}`
          : match,
    )
    .replace(
      /(["'])([^"'\r\n\\]{1,128})\1(\s*[:=]\s*)[^"',\s)}\]]+/g,
      (match: string, keyQuote: string, key: string, separator: string) =>
        isCredentialFieldName(key)
          ? `${keyQuote}${key}${keyQuote}${separator}[redacted]`
          : match,
    )
    .replace(
      /\b((?:[a-z0-9]+[_-])?authorization)\b\s*[:=]\s*["']?[^"',\r\n)}\]]+/gi,
      "$1=[redacted]",
    )
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, "$1 [redacted]")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[redacted-jwt]")
    .replace(
      /\b((?:[a-z0-9]+[_-])?(?:authorization|api[_-]?key|access[_-]?token|auth|bearer|client[_-]?secret|credential|password|passwd|private[_-]?key|refresh[_-]?token|secret(?:[_-]?[a-z0-9]+)*|session[_-]?token|token)(?:[_-]?[a-z0-9]+)*)\b\s*[:=]\s*["']?[^"',\s)}\]]+/gi,
      "$1=[redacted]",
    );
}

function redactCredentialHeaderValues(value: unknown): unknown {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return value;
  }

  const out: Record<string, unknown> = {};
  for (const [name, headerValue] of Object.entries(value as Record<string, unknown>)) {
    out[name] = isCredentialHeaderName(name) ? "[redacted]" : headerValue;
  }
  return out;
}

function redactCredentialHeaders(headers: Record<string, string>): {
  headers: Record<string, string>;
  redacted: boolean;
} {
  let redacted = false;
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (isCredentialHeaderName(name)) {
      out[name] = "[redacted]";
      redacted = true;
    } else {
      out[name] = value;
    }
  }
  return { headers: out, redacted };
}

export const secretNameSchema = z
  .string()
  .min(1)
  .max(256)
  .refine(noControl, "must not contain control characters");

export const httpMethodSchema = z.enum([
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
  "OPTIONS",
]);

export const httpUrlSchema = z
  .string()
  .min(1)
  .max(MAX_URL_LENGTH)
  .url()
  .refine((value) => {
    try {
      const url = new URL(value);
      return url.protocol === "http:" || url.protocol === "https:";
    } catch {
      return false;
    }
  }, "url must use http or https")
  .refine(
    isCredentialFreeUrl,
    "url must not include username/password or credential-shaped query parameters",
  );

export const httpsUrlSchema = z
  .string()
  .min(1)
  .max(MAX_URL_LENGTH)
  .url()
  .refine((value) => {
    try {
      return new URL(value).protocol === "https:";
    } catch {
      return false;
    }
  }, "url must use https")
  .refine(
    isCredentialFreeUrl,
    "url must not include username/password or credential-shaped query parameters",
  );

export const base64Schema = z
  .string()
  .max(MAX_BODY_B64_LENGTH)
  .refine((value) => BASE64_RE.test(value), "must be valid standard base64")
  .refine(
    (value) => decodedBase64Length(value) <= MAX_BODY_BYTES,
    `decoded body must be at most ${MAX_BODY_BYTES} bytes`,
  );

export const rfc3339ishSchema = z
  .string()
  .regex(RFC3339ISH_RE, "must be an RFC3339 timestamp");

export const resultLimitSchema = z.number().int().min(1).max(1000);

export const headerNameSchema = z
  .string()
  .min(1)
  .max(MAX_HEADER_NAME_LENGTH)
  .regex(HEADER_NAME_RE, "must be a valid HTTP header name");

const inputHeaderNameSchema = headerNameSchema.refine(
  (value) => !isCredentialHeaderName(value),
  "credential-bearing headers are not accepted as input",
).refine(
  (value) => !isRequestControlHeaderName(value),
  "request-control headers are not accepted as input",
);

export const authHeaderNameSchema = headerNameSchema.refine(
  (value) => !isRequestControlHeaderName(value),
  "request-control headers cannot be used for auth",
);

const headerValueSchema = z
  .string()
  .max(MAX_HEADER_VALUE_LENGTH)
  .refine((value) => !/[\r\n]/.test(value), "must not contain CR/LF");

export const headersSchema = z
  .record(inputHeaderNameSchema, headerValueSchema)
  .superRefine(validateHeaderEnvelope);

export const outputHeadersSchema = z
  .record(headerNameSchema, headerValueSchema)
  .superRefine(validateHeaderEnvelope);

export const scopeSchema = z.record(z.unknown()).superRefine((scope, ctx) => {
  if (jsonByteLength(scope) > MAX_SCOPE_BYTES) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: `scope must be at most ${MAX_SCOPE_BYTES} bytes as JSON`,
    });
  }
  validateScopeValue(scope, ctx, [], { keys: 0 });
});

export const ttlSecondsSchema = z.number().int().min(1).max(MAX_TTL_SECONDS);

const tagSchema = z
  .string()
  .min(1)
  .max(128)
  .refine(noControl, "must not contain control characters");

const secretKindSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[A-Za-z0-9._:-]+$/, "must be a valid secret kind");

export const secretMetadataSchema = z
  .object({
    name: secretNameSchema,
    kind: secretKindSchema,
    tags: z.array(tagSchema).max(128),
    created_at: rfc3339ishSchema,
    updated_at: rfc3339ishSchema,
    version: z.number().int().nonnegative(),
  })
  .strip();

export const secretListSchema = z
  .object({
    secrets: z.array(secretMetadataSchema).max(10000),
  })
  .strip();

export const signRequestOutputSchema = z
  .object({
    headers: outputHeadersSchema,
  })
  .strip();

export const proxyResponseOutputSchema = z
  .object({
    status: z.number().int().min(100).max(599),
    headers: z.preprocess(redactCredentialHeaderValues, outputHeadersSchema),
    body_b64: z
      .string()
      .max(MAX_PROXY_RESPONSE_BODY_B64_LENGTH)
      .refine((value) => BASE64_RE.test(value), "must be valid standard base64"),
    redacted: z.boolean().default(false),
  })
  .strip()
  .transform((value) => {
    const redactedHeaders = redactCredentialHeaders(value.headers);
    return {
      ...value,
      headers: redactedHeaders.headers,
      redacted: value.redacted || redactedHeaders.redacted,
    };
  });

export const mintedTokenOutputSchema = z
  .object({
    token: z.string().min(1).max(MAX_DERIVED_TOKEN_LENGTH).refine(noControl),
    expires_at: rfc3339ishSchema,
  })
  .strip();

const auditPeerSchema = z
  .object({
    pid: z.number().int(),
    basename: z.string().min(1).max(255).refine(noControl),
    code_sig_hex: z.string().regex(HEX64_RE).nullable(),
  })
  .strip();

const auditEntrySchema = z
  .object({
    seq: z.number().int().nonnegative(),
    ts: rfc3339ishSchema,
    peer: auditPeerSchema,
    tool: z.string().min(1).max(128).refine(noControl),
    secret: secretNameSchema.nullable(),
    target: z.string().max(2048).refine(noControl).nullable(),
    result: z.enum(["started", "ok", "denied", "error"]),
    note: z.string().max(512).refine(noControl).nullable(),
    prev_hash: z.string().regex(HEX64_RE),
  })
  .strip();

export const auditQueryOutputSchema = z
  .object({
    entries: z.array(auditEntrySchema).max(1000),
  })
  .strip();

export const secretMetadataJsonSchema = {
  type: "object",
  properties: {
    name: { type: "string", minLength: 1, maxLength: 256 },
    kind: { type: "string", minLength: 1, maxLength: 64, pattern: "^[A-Za-z0-9._:-]+$" },
    tags: { type: "array", items: { type: "string", minLength: 1, maxLength: 128 }, maxItems: 128 },
    created_at: { type: "string", format: "date-time" },
    updated_at: { type: "string", format: "date-time" },
    version: { type: "integer", minimum: 0 },
  },
  required: ["name", "kind", "tags", "created_at", "updated_at", "version"],
  additionalProperties: false,
} as const;

export const secretListJsonSchema = {
  $schema: JSON_SCHEMA_URI,
  type: "object",
  properties: {
    secrets: { type: "array", items: secretMetadataJsonSchema, maxItems: 10000 },
  },
  required: ["secrets"],
  additionalProperties: false,
} as const;

export const headersJsonSchema = {
  type: "object",
  maxProperties: MAX_HEADER_COUNT,
  propertyNames: {
    type: "string",
    minLength: 1,
    maxLength: MAX_HEADER_NAME_LENGTH,
    pattern: "^[A-Za-z0-9!#$%&'*+\\-.^_`|~]+$",
  },
  additionalProperties: {
    type: "string",
    maxLength: MAX_HEADER_VALUE_LENGTH,
    not: { pattern: "[\\r\\n]" },
  },
} as const;

export const inputHeadersJsonSchema = {
  ...headersJsonSchema,
  propertyNames: {
    ...headersJsonSchema.propertyNames,
    not: {
      anyOf: [
        { pattern: SENSITIVE_FIELD_JSON_PATTERN },
        {
          pattern:
            "^(?:[Hh][Oo][Ss][Tt]|[Cc][Oo][Nn][Tt][Ee][Nn][Tt]-[Ll][Ee][Nn][Gg][Tt][Hh]|[Tt][Rr][Aa][Nn][Ss][Ff][Ee][Rr]-[Ee][Nn][Cc][Oo][Dd][Ii][Nn][Gg]|[Cc][Oo][Nn][Nn][Ee][Cc][Tt][Ii][Oo][Nn]|[Pp][Rr][Oo][Xx][Yy]-[Cc][Oo][Nn][Nn][Ee][Cc][Tt][Ii][Oo][Nn]|[Uu][Pp][Gg][Rr][Aa][Dd][Ee]|[Kk][Ee][Ee][Pp]-[Aa][Ll][Ii][Vv][Ee]|[Tt][Ee]|[Tt][Rr][Aa][Ii][Ll][Ee][Rr]|[Ee][Xx][Pp][Ee][Cc][Tt])$",
        },
      ],
    },
  },
} as const;

function scopeValueJsonSchema(depth: number): unknown {
  const scalar = [
    {
      type: "string",
      maxLength: MAX_SCOPE_STRING_LENGTH,
      not: { pattern: CONTROL_JSON_PATTERN },
    },
    { type: "number" },
    { type: "boolean" },
    { type: "null" },
  ];
  if (depth <= 0) {
    return { anyOf: scalar };
  }
  const child = scopeValueJsonSchema(depth - 1);
  return {
    anyOf: [
      ...scalar,
      { type: "array", maxItems: MAX_SCOPE_ARRAY_ITEMS, items: child },
      {
        type: "object",
        maxProperties: MAX_SCOPE_KEYS,
        propertyNames: {
          type: "string",
          maxLength: 128,
          not: {
            anyOf: [
              { pattern: CONTROL_JSON_PATTERN },
              { pattern: SENSITIVE_FIELD_JSON_PATTERN },
            ],
          },
        },
        additionalProperties: child,
      },
    ],
  };
}

export const scopeJsonSchema = {
  type: "object",
  maxProperties: MAX_SCOPE_KEYS,
  propertyNames: {
    type: "string",
    maxLength: 128,
    not: {
      anyOf: [
        { pattern: CONTROL_JSON_PATTERN },
        { pattern: SENSITIVE_FIELD_JSON_PATTERN },
      ],
    },
  },
  additionalProperties: scopeValueJsonSchema(MAX_SCOPE_DEPTH - 1),
} as const;

export const signRequestOutputJsonSchema = {
  $schema: JSON_SCHEMA_URI,
  type: "object",
  properties: {
    headers: headersJsonSchema,
  },
  required: ["headers"],
  additionalProperties: false,
} as const;

export const proxyResponseOutputJsonSchema = {
  $schema: JSON_SCHEMA_URI,
  type: "object",
  properties: {
    status: { type: "integer", minimum: 100, maximum: 599 },
    headers: headersJsonSchema,
    body_b64: {
      type: "string",
      maxLength: MAX_PROXY_RESPONSE_BODY_B64_LENGTH,
      pattern: "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
    },
    redacted: { type: "boolean" },
  },
  required: ["status", "headers", "body_b64", "redacted"],
  additionalProperties: false,
} as const;

export const mintedTokenOutputJsonSchema = {
  $schema: JSON_SCHEMA_URI,
  type: "object",
  properties: {
    token: { type: "string", minLength: 1, maxLength: MAX_DERIVED_TOKEN_LENGTH },
    expires_at: { type: "string", format: "date-time" },
  },
  required: ["token", "expires_at"],
  additionalProperties: false,
} as const;

export const auditQueryOutputJsonSchema = {
  $schema: JSON_SCHEMA_URI,
  type: "object",
  properties: {
    entries: {
      type: "array",
      maxItems: 1000,
      items: {
        type: "object",
        properties: {
          seq: { type: "integer", minimum: 0 },
          ts: { type: "string", format: "date-time" },
          peer: {
            type: "object",
            properties: {
              pid: { type: "integer" },
              basename: { type: "string", minLength: 1, maxLength: 255 },
              code_sig_hex: { type: ["string", "null"], pattern: "^[a-f0-9]{64}$" },
            },
            required: ["pid", "basename", "code_sig_hex"],
            additionalProperties: false,
          },
          tool: { type: "string", minLength: 1, maxLength: 128 },
          secret: { type: ["string", "null"], minLength: 1, maxLength: 256 },
          target: { type: ["string", "null"], maxLength: 2048 },
          result: { type: "string", enum: ["started", "ok", "denied", "error"] },
          note: { type: ["string", "null"], maxLength: 512 },
          prev_hash: { type: "string", pattern: "^[a-f0-9]{64}$" },
        },
        required: ["seq", "ts", "peer", "tool", "secret", "target", "result", "note", "prev_hash"],
        additionalProperties: false,
      },
    },
  },
  required: ["entries"],
  additionalProperties: false,
} as const;
