import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { startMockDaemon, type MockServer } from "./mock-daemon.ts";

let mock: MockServer | null = null;

async function withMock(handlers: Record<string, (p: unknown) => unknown>) {
  mock = await startMockDaemon({ handlers });
  process.env["CLOAK_UNSAFE_TEST_MODE"] = "1";
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
  delete process.env["CLOAK_SOCK"];
  delete process.env["CLOAK_UNSAFE_TEST_MODE"];
  if (mock) {
    await mock.close();
    mock = null;
  }
});

describe("tools", () => {
  test("redacts authorization schemes in daemon error text", async () => {
    const { redactText } = await import("../src/tools/validation.ts");

    const bearer = redactText("cloakd error: Authorization: Bearer bearer-secret-demo-abc123");
    expect(bearer).not.toContain("bearer-secret-demo-abc123");
    expect(bearer).toContain("[redacted]");

    const basic = redactText("upstream failed with Authorization: Basic dXNlcjpwYXNz");
    expect(basic).not.toContain("dXNlcjpwYXNz");
    expect(basic).toContain("[redacted]");

    const token = redactText("upstream failed with Authorization: token REDACTED_TEST_GITHUB_TOKEN");
    expect(token).not.toContain("REDACTED_TEST_GITHUB_TOKEN");
    expect(token).toContain("[redacted]");

    const apiKey = redactText("upstream failed with Authorization: ApiKey sk_live_secret123");
    expect(apiKey).not.toContain("sk_live_secret123");
    expect(apiKey).toContain("[redacted]");

    const jsonApiKey = redactText('upstream error {"api_key":"json-secret-demo-abc123"}');
    expect(jsonApiKey).not.toContain("json-secret-demo-abc123");
    expect(jsonApiKey).toContain('"api_key":"[redacted]"');

    const jsonClientSecret = redactText("upstream error {'client_secret':'shh'}");
    expect(jsonClientSecret).not.toContain("shh");
    expect(jsonClientSecret).toContain("'client_secret':'[redacted]'");
  });

  test("redacts JSON-style credential fields in daemon tool errors", async () => {
    await withMock({
      "mcp.handshake": () => ({ session_token: "tok" }),
      "vault.list": () => ({
        __error: {
          code: "upstream",
          message: 'upstream error {"api_key":"json-secret-demo-abc123"}',
        },
      }),
    });
    const ipc = await import("../src/ipc.ts");
    await ipc.handshake();
    const { dispatchTool } = await import("../src/tools/index.ts");
    const out = await dispatchTool("list_secret_names", {});
    expect(out.isError).toBe(true);
    expect(out.content[0].text).not.toContain("json-secret-demo-abc123");
    expect(out.content[0].text).toContain('"api_key":"[redacted]"');
  });

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
    expect(bad.isError).toBe(true);
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
      aws_region: "us-west-2",
      aws_service: "execute-api",
    });
    const parsed = JSON.parse(out.content[0].text);
    expect(parsed.headers.Authorization).toContain("AWS4-HMAC-SHA256");
    expect((received as { secret_name: string }).secret_name).toBe("aws");
    expect((received as { aws_region: string }).aws_region).toBe("us-west-2");
    expect((received as { aws_service: string }).aws_service).toBe("execute-api");
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

  test("tools advertise output schemas and strip credential-shaped daemon extras", async () => {
    const prevHash = "0".repeat(64);
    await withMock({
      "mcp.handshake": () => ({ session_token: "tok" }),
      "vault.list": () => ({
        secrets: [
          {
            name: "a",
            kind: "bearer",
            tags: [],
            created_at: "2026-01-01T00:00:00Z",
            updated_at: "2026-01-01T00:00:00Z",
            version: 1,
            secret_value: "should-not-cross",
          },
        ],
      }),
      "vault.get_metadata": () => ({
        name: "a",
        kind: "bearer",
        tags: [],
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
        version: 1,
        password: "should-not-cross",
      }),
      "tool.sign_request": () => ({
        headers: { Authorization: "AWS4-HMAC-SHA256 signed" },
        token: "should-not-cross",
      }),
      "tool.proxy_http": () => ({
        status: 200,
        headers: { "content-type": "application/json", "set-cookie": "session=should-not-cross" },
        body_b64: Buffer.from(`{"ok":true}`, "utf8").toString("base64"),
        request: { headers: { Authorization: "should-not-cross" } },
      }),
      "tool.mint_token": () => ({
        token: "short-lived-token",
        expires_at: "2026-01-01T01:00:00Z",
        secret_access_key: "should-not-cross",
      }),
      "tool.query_audit": () => ({
        entries: [
          {
            seq: 1,
            ts: "2026-01-01T00:00:00Z",
            peer: { pid: 123, basename: "cloak-mcp", code_sig_hex: null, api_key: "should-not-cross" },
            tool: "tool.proxy_http",
            secret: "a",
            target: "api.example.com",
            result: "started",
            note: "auth_scheme=bearer egress-started",
            prev_hash: prevHash,
            secret_value: "should-not-cross",
          },
        ],
        credential: "should-not-cross",
      }),
    });

    const ipc = await import("../src/ipc.ts");
    await ipc.handshake();
    const { dispatchTool, tools } = await import("../src/tools/index.ts");

    for (const tool of tools) {
      expect((tool.outputSchema as { type?: string }).type).toBe("object");
      expect((tool.outputSchema as { additionalProperties?: boolean }).additionalProperties).toBe(false);
    }

    const outputs = [
      await dispatchTool("list_secret_names", {}),
      await dispatchTool("get_secret_metadata", { name: "a" }),
      await dispatchTool("sign_request", {
        secret_name: "a",
        scheme: "aws-sigv4",
        method: "GET",
        url: "https://example.com/",
      }),
      await dispatchTool("proxy_authenticated_http_request", {
        secret_name: "a",
        method: "GET",
        url: "https://example.com/",
        auth_scheme: "bearer",
      }),
      await dispatchTool("mint_short_lived_token", { secret_name: "a", kind: "aws-sts" }),
      await dispatchTool("query_audit", {}),
    ];

    for (const output of outputs) {
      expect(output.isError).toBeUndefined();
      expect(output.structuredContent).toBeDefined();
      expect(JSON.stringify(output.structuredContent)).not.toContain("should-not-cross");
      expect(output.content[0].text).not.toContain("should-not-cross");
    }

    expect(outputs[3].structuredContent?.headers).toEqual({
      "content-type": "application/json",
      "set-cookie": "[redacted]",
    });
    expect(outputs[3].structuredContent?.redacted).toBe(true);
    expect(outputs[4].structuredContent?.token).toBe("short-lived-token");
    expect(outputs[5].structuredContent?.entries).toEqual([
      {
        seq: 1,
        ts: "2026-01-01T00:00:00Z",
        peer: { pid: 123, basename: "cloak-mcp", code_sig_hex: null },
        tool: "tool.proxy_http",
        secret: "a",
        target: "api.example.com",
        result: "started",
        note: "auth_scheme=bearer egress-started",
        prev_hash: prevHash,
      },
    ]);
  });

  test("metadata tools strip unapproved daemon fields", async () => {
    await withMock({
      "mcp.handshake": () => ({ session_token: "tok" }),
      "vault.list": () => ({
        secrets: [
          {
            name: "a",
            kind: "bearer",
            tags: [],
            created_at: "2026-01-01T00:00:00Z",
            updated_at: "2026-01-01T00:00:00Z",
            version: 1,
            value: "should-not-cross",
          },
        ],
        plaintext: "should-not-cross",
      }),
      "vault.get_metadata": () => ({
        name: "a",
        kind: "bearer",
        tags: [],
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
        version: 1,
        secret_value: "should-not-cross",
      }),
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

  test("metadata tools reject invalid daemon shapes", async () => {
    await withMock({
      "mcp.handshake": () => ({ session_token: "tok" }),
      "vault.list": () => ({
        secrets: [{ name: "a", kind: "bearer", tags: [], created_at: "not-a-date", updated_at: "2026-01-01T00:00:00Z", version: 1 }],
      }),
    });
    const ipc = await import("../src/ipc.ts");
    await ipc.handshake();
    const { dispatchTool } = await import("../src/tools/index.ts");
    const out = await dispatchTool("list_secret_names", {});
    expect(out.isError).toBe(true);
    expect(out.content[0].text).toContain("RFC3339");
  });

  test("tool argument schemas reject unsafe or incomplete inputs", async () => {
    await withMock({
      "mcp.handshake": () => ({ session_token: "tok" }),
      "tool.proxy_http": () => ({ status: 200, headers: {}, body_b64: "" }),
      "tool.sign_request": () => ({ headers: {} }),
      "tool.query_audit": () => ({ entries: [] }),
    });
    const ipc = await import("../src/ipc.ts");
    await ipc.handshake();
    const { dispatchTool } = await import("../src/tools/index.ts");

    const badProxy = await dispatchTool("proxy_authenticated_http_request", {
      secret_name: "github",
      method: "GET",
      url: "https://api.github.com/user",
      auth_scheme: "header",
    });
    expect(badProxy.isError).toBe(true);
    expect(badProxy.content[0].text).toContain("header_name is required");

    const badSign = await dispatchTool("sign_request", {
      secret_name: "aws",
      scheme: "hmac-sha256",
      method: "TRACE",
      url: "https://example.com",
      body_b64: "not-base64",
    });
    expect(badSign.isError).toBe(true);
    expect(badSign.content[0].text).toContain("Invalid enum value");
    expect(badSign.content[0].text).toContain("base64");

    const badAudit = await dispatchTool("query_audit", {
      since: "2026-01-01",
      limit: 1001,
    });
    expect(badAudit.isError).toBe(true);
    expect(badAudit.content[0].text).toContain("RFC3339");

    const plaintextProxy = await dispatchTool("proxy_authenticated_http_request", {
      secret_name: "github",
      method: "GET",
      url: "http://api.github.com/user",
      auth_scheme: "bearer",
    });
    expect(plaintextProxy.isError).toBe(true);
    expect(plaintextProxy.content[0].text).toContain("https");

    const credentialHeaderProxy = await dispatchTool("proxy_authenticated_http_request", {
      secret_name: "github",
      method: "GET",
      url: "https://api.github.com/user",
      auth_scheme: "bearer",
      headers: { Authorization: "Bearer pasted-token" },
    });
    expect(credentialHeaderProxy.isError).toBe(true);
    expect(credentialHeaderProxy.content[0].text).toContain("credential-bearing headers");

    const camelCredentialHeaderProxy = await dispatchTool("proxy_authenticated_http_request", {
      secret_name: "github",
      method: "GET",
      url: "https://api.github.com/user",
      auth_scheme: "bearer",
      headers: { "X-AccessToken": "pasted-token" },
    });
    expect(camelCredentialHeaderProxy.isError).toBe(true);
    expect(camelCredentialHeaderProxy.content[0].text).toContain("credential-bearing headers");

    const controlHeaderProxy = await dispatchTool("proxy_authenticated_http_request", {
      secret_name: "github",
      method: "GET",
      url: "https://api.github.com/user",
      auth_scheme: "bearer",
      headers: { Host: "attacker.example" },
    });
    expect(controlHeaderProxy.isError).toBe(true);
    expect(controlHeaderProxy.content[0].text).toContain("request-control headers");

    const controlAuthHeaderProxy = await dispatchTool("proxy_authenticated_http_request", {
      secret_name: "github",
      method: "GET",
      url: "https://api.github.com/user",
      auth_scheme: "header",
      header_name: "Host",
    });
    expect(controlAuthHeaderProxy.isError).toBe(true);
    expect(controlAuthHeaderProxy.content[0].text).toContain("request-control headers");

    for (const url of [
      "https://user:pass@api.github.com/user",
      "https://api.github.com/user?api_key=pasted-token",
      "https://api.github.com/user?accessToken=pasted-token",
    ]) {
      const credentialUrlProxy = await dispatchTool("proxy_authenticated_http_request", {
        secret_name: "github",
        method: "GET",
        url,
        auth_scheme: "bearer",
      });
      expect(credentialUrlProxy.isError).toBe(true);
      expect(credentialUrlProxy.content[0].text).toContain("credential");
    }

    const credentialUrlSign = await dispatchTool("sign_request", {
      secret_name: "aws",
      scheme: "hmac-sha256",
      method: "GET",
      url: "https://example.com/?clientSecret=pasted-token",
    });
    expect(credentialUrlSign.isError).toBe(true);
    expect(credentialUrlSign.content[0].text).toContain("credential");

    const controlHeaderSign = await dispatchTool("sign_request", {
      secret_name: "aws",
      scheme: "hmac-sha256",
      method: "GET",
      url: "https://example.com/",
      headers: { "Transfer-Encoding": "chunked" },
    });
    expect(controlHeaderSign.isError).toBe(true);
    expect(controlHeaderSign.content[0].text).toContain("request-control headers");

    const queryAuthProxy = await dispatchTool("proxy_authenticated_http_request", {
      secret_name: "github",
      method: "GET",
      url: "https://api.github.com/user",
      auth_scheme: "query",
      query_name: "api_key",
    });
    expect(queryAuthProxy.isError).toBe(true);
    expect(queryAuthProxy.content[0].text).toContain("Invalid enum value");

    const tooManyHeaders = Object.fromEntries(
      Array.from({ length: 65 }, (_, i) => [`x-test-${i}`, "ok"]),
    );
    const headerFlood = await dispatchTool("sign_request", {
      secret_name: "aws",
      scheme: "hmac-sha256",
      method: "GET",
      url: "https://example.com",
      headers: tooManyHeaders,
    });
    expect(headerFlood.isError).toBe(true);
    expect(headerFlood.content[0].text).toContain("at most 64 headers");

    const longLivedMint = await dispatchTool("mint_short_lived_token", {
      secret_name: "aws",
      kind: "aws-sts",
      ttl_seconds: 3601,
    });
    expect(longLivedMint.isError).toBe(true);
    expect(longLivedMint.content[0].text).toContain("less than or equal to 3600");

    const credentialScope = await dispatchTool("mint_short_lived_token", {
      secret_name: "aws",
      kind: "aws-sts",
      scope: { session_token: "pasted-token" },
    });
    expect(credentialScope.isError).toBe(true);
    expect(credentialScope.content[0].text).toContain("credential-shaped fields");

    const camelCredentialScope = await dispatchTool("mint_short_lived_token", {
      secret_name: "aws",
      kind: "aws-sts",
      scope: { clientSecret: "pasted-token" },
    });
    expect(camelCredentialScope.isError).toBe(true);
    expect(camelCredentialScope.content[0].text).toContain("credential-shaped fields");
  });

  test("unknown tools are marked as MCP tool errors", async () => {
    const { dispatchTool } = await import("../src/tools/index.ts");
    const out = await dispatchTool("does_not_exist", {});
    expect(out.isError).toBe(true);
    expect(out.content[0].text).toContain("unknown tool");
  });

  test("tool descriptions match the locked contract", async () => {
    const { tools } = await import("../src/tools/index.ts");
    const desc = (n: string) => tools.find((t) => t.name === n)?.description;
    expect(desc("list_secret_names")).toBe(
      "List the names and metadata of secrets stored in the local Cloak vault. Returns names, kinds, and tags only, never the secret values themselves.",
    );
    expect(desc("get_secret_metadata")).toBe(
      "Return metadata about a single named secret (kind, tags, created/updated timestamps, version). Never returns the secret value.",
    );
    expect(desc("sign_request")).toBe(
      "Compute authentication headers for an outbound HTTP request by signing it with a stored secret. Supports only AWS SigV4 and generic HMAC-SHA256, and returns just the computed headers; the secret is never disclosed. Use this only for APIs that require request signing, such as AWS services. For normal API-key or bearer-token auth (Stripe, OpenAI, GitHub, and the like), use proxy_authenticated_http_request instead.",
    );
    expect(desc("proxy_authenticated_http_request")).toBe(
      "Make an authenticated HTTPS API call using a stored secret as the credential. This is the primary way to call an external API that authenticates with an API key or token (for example Stripe, OpenAI, GitHub, or Slack): the daemon attaches the named secret as a Bearer token, HTTP Basic credential, or custom header, sends the request to a host on the user's allowlist, and returns the status, redacted headers, and base64-encoded body. The secret value is never disclosed to you. Query-string auth is disabled because URLs are commonly logged.",
    );
    expect(desc("mint_short_lived_token")).toBe(
      "Mint a short-lived derived token from a long-lived parent secret. AWS STS is implemented; GitHub App and GitLab PAT kinds are reserved and currently return not-supported. Returns the derived token and its expiry. The long-lived parent never leaves the daemon.",
    );
    expect(desc("query_audit")).toBe(
      "Query the local Cloak audit log of privileged operations. Filterable by time range, tool name, secret name, and result. Returns audit entries, never secret values.",
    );
    expect(tools.length).toBe(6);
  });

  test("tool input schemas use only keywords the model tool-schema validator accepts", async () => {
    const { tools } = await import("../src/tools/index.ts");
    // The Anthropic tool-input-schema validator silently DROPS any tool whose
    // advertised schema uses an unsupported keyword (the proxy tool once used
    // if/then/allOf and vanished from every agent's toolset). A blacklist only
    // catches keywords we already know are fatal; this is a WHITELIST, so a
    // future tool added with oneOf/$ref/dependencies/if-variants/etc. fails
    // here loudly instead of disappearing in the real client. Any conditional
    // or cross-field validation must live in the runtime zod schema instead.
    //
    // Empirically accepted (and therefore allowed): the simple structural
    // keywords plus `not`, `propertyNames`, and `anyOf` (sign_request and the
    // proxy advertise `anyOf` and were both used by live agents).
    const ALLOWED = new Set([
      "$schema", "type", "properties", "required", "additionalProperties",
      "description", "enum", "items", "not", "anyOf", "propertyNames",
      "pattern", "format", "minLength", "maxLength", "minItems", "maxItems",
      "minimum", "maximum", "minProperties", "maxProperties",
    ]);
    // Keys whose values are NOT subschemas (so their contents are data, not
    // keywords): do not recurse into them.
    const LEAF = new Set([
      "type", "required", "enum", "description", "format", "pattern",
      "default", "examples", "title", "$schema", "$id", "$ref", "const",
      "minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems",
      "minProperties", "maxProperties", "multipleOf",
    ]);
    const collect = (node: unknown, out: Set<string>): void => {
      if (Array.isArray(node)) {
        for (const x of node) collect(x, out);
        return;
      }
      if (node === null || typeof node !== "object") return;
      for (const [key, val] of Object.entries(node as Record<string, unknown>)) {
        out.add(key);
        if (key === "properties" || key === "patternProperties" || key === "$defs" || key === "definitions") {
          if (val && typeof val === "object") {
            for (const sub of Object.values(val as Record<string, unknown>)) collect(sub, out);
          }
        } else if (!LEAF.has(key)) {
          collect(val, out);
        }
      }
    };
    for (const t of tools) {
      const used = new Set<string>();
      collect(t.inputSchema, used);
      for (const kw of used) {
        expect(`${t.name} schema keyword '${kw}' allowed: ${ALLOWED.has(kw)}`).toBe(
          `${t.name} schema keyword '${kw}' allowed: true`,
        );
      }
    }
  });
});
