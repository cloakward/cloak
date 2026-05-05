import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { startMockDaemon, type MockServer } from "./mock-daemon.ts";

let mock: MockServer | null = null;

async function withMock(handlers: Record<string, (p: unknown) => unknown>) {
  mock = await startMockDaemon({ handlers });
  process.env["CLOAK_SOCK"] = mock.path;
  // Re-import ipc fresh so its module-level state is clean.
  // bun-test re-runs each test file isolated, but within a file we explicitly
  // reset state between tests.
  const ipc = await import("../src/ipc.ts");
  ipc._resetForTests();
  return ipc;
}

afterEach(async () => {
  // Reset ipc module state and tear down mock.
  const ipc = await import("../src/ipc.ts");
  ipc._resetForTests();
  if (mock) {
    await mock.close();
    mock = null;
  }
});

describe("tools", () => {
  test("list_secret_names returns names array", async () => {
    await withMock({
      "mcp.handshake": () => ({ session_token: "tok" }),
      "vault.list": () => ({
        secrets: [
          { name: "github", kind: "bearer", tags: [], created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z", version: 1 },
          { name: "openai", kind: "bearer", tags: ["llm"], created_at: "2026-02-01T00:00:00Z", updated_at: "2026-02-01T00:00:00Z", version: 1 },
        ],
      }),
    });
    const ipc = await import("../src/ipc.ts");
    await ipc.handshake();
    const { dispatchTool } = await import("../src/tools/index.ts");
    const out = await dispatchTool("list_secret_names", {});
    expect(out.content[0].type).toBe("text");
    const parsed = JSON.parse(out.content[0].text);
    expect(parsed.secrets.map((s: { name: string }) => s.name)).toEqual(["github", "openai"]);
  });

  test("get_secret_metadata returns metadata for known and error for unknown", async () => {
    await withMock({
      "mcp.handshake": () => ({ session_token: "tok" }),
      "vault.get_metadata": (params: unknown) => {
        const p = params as { name: string };
        if (p.name === "github") {
          return { name: "github", kind: "bearer", tags: ["scm"], created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-02T00:00:00Z", version: 2 };
        }
        return { __error: { code: "not_found", message: `secret '${p.name}' not found` } };
      },
    });
    const ipc = await import("../src/ipc.ts");
    await ipc.handshake();
    const { dispatchTool } = await import("../src/tools/index.ts");

    const ok = await dispatchTool("get_secret_metadata", { name: "github" });
    const okParsed = JSON.parse(ok.content[0].text);
    expect(okParsed.name).toBe("github");
    expect(okParsed.version).toBe(2);

    const bad = await dispatchTool("get_secret_metadata", { name: "nope" });
    expect(bad.content[0].text.startsWith("error:")).toBe(true);
    expect(bad.content[0].text).toContain("not_found");
  });

  test("sign_request round-trips params and returns headers", async () => {
    let received: unknown = null;
    await withMock({
      "mcp.handshake": () => ({ session_token: "tok" }),
      "tool.sign_request": (params: unknown) => {
        received = params;
        return { headers: { Authorization: "AWS4-HMAC-SHA256 ...", "x-amz-date": "20260101T000000Z" } };
      },
    });
    const ipc = await import("../src/ipc.ts");
    await ipc.handshake();
    const { dispatchTool } = await import("../src/tools/index.ts");
    const out = await dispatchTool("sign_request", {
      secret_name: "aws",
      scheme: "aws-sigv4",
      method: "GET",
      url: "https://example.amazonaws.com/foo",
    });
    const parsed = JSON.parse(out.content[0].text);
    expect(parsed.headers.Authorization).toContain("AWS4-HMAC-SHA256");
    expect((received as { secret_name: string }).secret_name).toBe("aws");
  });

  test("proxy_authenticated_http_request returns formatted status+headers+body", async () => {
    await withMock({
      "mcp.handshake": () => ({ session_token: "tok" }),
      "tool.proxy_http": () => ({
        status: 200,
        headers: { "content-type": "application/json", "x-trace": "abc" },
        body_b64: Buffer.from(`{"login":"octocat"}`, "utf8").toString("base64"),
      }),
    });
    const ipc = await import("../src/ipc.ts");
    await ipc.handshake();
    const { dispatchTool } = await import("../src/tools/index.ts");
    const out = await dispatchTool("proxy_authenticated_http_request", {
      secret_name: "github",
      method: "GET",
      url: "https://api.github.com/user",
      auth_scheme: "bearer",
    });
    const text = out.content[0].text;
    expect(text.startsWith("Status 200")).toBe(true);
    expect(text).toContain("content-type: application/json");
    expect(text).toContain(`{"login":"octocat"}`);
  });

  test("proxy_authenticated_http_request shows binary marker for non-printable bodies", async () => {
    await withMock({
      "mcp.handshake": () => ({ session_token: "tok" }),
      "tool.proxy_http": () => ({
        status: 200,
        headers: {},
        body_b64: Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd, 0x00, 0x01]).toString("base64"),
      }),
    });
    const ipc = await import("../src/ipc.ts");
    await ipc.handshake();
    const { dispatchTool } = await import("../src/tools/index.ts");
    const out = await dispatchTool("proxy_authenticated_http_request", {
      secret_name: "x",
      method: "GET",
      url: "https://example.com/blob",
      auth_scheme: "bearer",
    });
    expect(out.content[0].text).toContain("<binary,");
  });

  test("no tool returns plaintext-looking secret material", async () => {
    // Property-ish: even if the daemon misbehaves and stuffs a 'secret' field
    // into a metadata response, the shim does not synthesize one. We assert
    // that what comes back is exactly what the daemon returned (echoed),
    // so the responsibility is correctly delegated. The shim never injects
    // a `value`/`secret`/`plaintext` field of its own.
    await withMock({
      "mcp.handshake": () => ({ session_token: "tok" }),
      "vault.list": () => ({ secrets: [{ name: "a", kind: "bearer", tags: [], created_at: "x", updated_at: "x", version: 1 }] }),
      "vault.get_metadata": () => ({ name: "a", kind: "bearer", tags: [], created_at: "x", updated_at: "x", version: 1 }),
    });
    const ipc = await import("../src/ipc.ts");
    await ipc.handshake();
    const { dispatchTool } = await import("../src/tools/index.ts");
    const a = await dispatchTool("list_secret_names", {});
    const b = await dispatchTool("get_secret_metadata", { name: "a" });
    for (const t of [a.content[0].text, b.content[0].text]) {
      expect(t.toLowerCase()).not.toContain("\"value\":");
      expect(t.toLowerCase()).not.toContain("\"plaintext\":");
      expect(t.toLowerCase()).not.toContain("\"secret_value\":");
    }
  });

  test("tool descriptions match the locked contract", async () => {
    const { tools } = await import("../src/tools/index.ts");
    const desc = (n: string) => tools.find((t) => t.name === n)?.description;
    expect(desc("list_secret_names")).toBe(
      "List the names and metadata of secrets stored in the local Cloak vault. Returns names, kinds, and tags only — never the secret values themselves.",
    );
    expect(desc("get_secret_metadata")).toBe(
      "Return metadata about a single named secret (kind, tags, created/updated timestamps, version). Never returns the secret value.",
    );
    expect(desc("sign_request")).toBe(
      "Compute authentication headers for an outbound HTTP request using a stored secret as the signing key. Supports AWS SigV4 and generic HMAC-SHA256. Returns only the computed headers — the underlying secret is never disclosed. Use this when an API requires request signing rather than a bearer token.",
    );
    expect(desc("proxy_authenticated_http_request")).toBe(
      "Send an HTTP request to a host on the user's allowlist, with the named secret attached by the daemon as authentication. The request and response transit the local daemon, never this tool. Returns status, headers, and base64-encoded body. The auth header is stripped from the echoed request metadata. Use this to call APIs (GitHub, OpenAI, Stripe, etc.) without ever handling the key.",
    );
    expect(desc("mint_short_lived_token")).toBe(
      "Mint a short-lived derived token from a long-lived parent secret. Examples: STS session credentials from an AWS access key, an installation token from a GitHub App private key, a scoped PAT from a parent PAT. Returns the derived token and its expiry. The long-lived parent never leaves the daemon.",
    );
    expect(desc("query_audit")).toBe(
      "Query the local Cloak audit log of privileged operations. Filterable by time range, tool name, secret name, and result. Returns audit entries — never secret values.",
    );
    expect(tools.length).toBe(6);
  });
});
