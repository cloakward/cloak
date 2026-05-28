import { z } from "zod";

const RFC3339ISH_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const BASE64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const HEADER_NAME_RE = /^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/;
const CONTROL_RE = /[\u0000-\u001f\u007f]/;

export const secretNameSchema = z
  .string()
  .min(1)
  .max(256)
  .refine((value) => !CONTROL_RE.test(value), "must not contain control characters");

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
  .url()
  .refine((value) => {
    try {
      const url = new URL(value);
      return url.protocol === "http:" || url.protocol === "https:";
    } catch {
      return false;
    }
  }, "url must use http or https");

export const httpsUrlSchema = z
  .string()
  .url()
  .refine((value) => {
    try {
      return new URL(value).protocol === "https:";
    } catch {
      return false;
    }
  }, "url must use https");

export const base64Schema = z
  .string()
  .refine((value) => BASE64_RE.test(value), "must be valid standard base64");

export const rfc3339ishSchema = z
  .string()
  .regex(RFC3339ISH_RE, "must be an RFC3339 timestamp");

export const resultLimitSchema = z.number().int().min(1).max(1000);

export const headerNameSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(HEADER_NAME_RE, "must be a valid HTTP header name");

export const queryNameSchema = z
  .string()
  .min(1)
  .max(128)
  .refine((value) => !CONTROL_RE.test(value), "must not contain control characters");

export const headersSchema = z.record(
  headerNameSchema,
  z.string().max(8192).refine((value) => !/[\r\n]/.test(value), "must not contain CR/LF"),
);

const tagSchema = z
  .string()
  .min(1)
  .max(128)
  .refine((value) => !CONTROL_RE.test(value), "must not contain control characters");

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
