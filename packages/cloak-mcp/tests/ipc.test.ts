import { describe, test, expect, afterEach } from "bun:test";
import { startMockDaemon, type MockServer } from "./mock-daemon.ts";

let mock: MockServer | null = null;
const originalArgv = [...process.argv];

afterEach(async () => {
  const ipc = await import("../src/ipc.ts");
  ipc._resetForTests();
  process.argv = [...originalArgv];
  delete process.env["CLOAK_SOCK"];
  delete process.env["CLOAK_UNSAFE_TEST_MODE"];
  if (mock) {
    await mock.close();
    mock = null;
  }
});

describe("ipc", () => {
  test("oversized inbound frame (>4 MiB) is rejected", async () => {
    mock = await startMockDaemon({
      handlers: {
        "vault.list": () => ({ secrets: [] }),
      },
      oversize: true,
    });
    process.env["CLOAK_UNSAFE_TEST_MODE"] = "1";
    process.env["CLOAK_SOCK"] = mock.path;
    const ipc = await import("../src/ipc.ts");
    ipc._resetForTests();
    await expect(ipc.request("vault.list", {})).rejects.toThrow(/too large/i);
  });

  test("malformed JSON response yields a friendly error", async () => {
    mock = await startMockDaemon({
      handlers: {
        "vault.list": () => ({ secrets: [] }),
      },
      malformedJson: true,
    });
    process.env["CLOAK_UNSAFE_TEST_MODE"] = "1";
    process.env["CLOAK_SOCK"] = mock.path;
    const ipc = await import("../src/ipc.ts");
    ipc._resetForTests();
    await expect(ipc.request("vault.list", {})).rejects.toThrow(/malformed json/i);
  });

  test("handshake stashes session token and subsequent requests include it", async () => {
    let lastSeenToken: string | undefined;
    mock = await startMockDaemon({
      handlers: {
        "mcp.handshake": () => ({ session_token: "deadbeef" }),
        "vault.list": (_params, req) => {
          lastSeenToken = req.session_token;
          return { secrets: [], _seen_token: lastSeenToken };
        },
      },
    });
    process.env["CLOAK_UNSAFE_TEST_MODE"] = "1";
    process.env["CLOAK_SOCK"] = mock.path;
    const ipc = await import("../src/ipc.ts");
    ipc._resetForTests();
    await ipc.handshake();
    await ipc.request("vault.list", {});
    expect(ipc._getSessionToken()).toBe("deadbeef");
    expect(lastSeenToken).toBe("deadbeef");
  });

  test("error response surfaces code and message", async () => {
    mock = await startMockDaemon({
      handlers: {
        "vault.list": () => ({ __error: { code: "denied", message: "policy says no" } }),
      },
    });
    process.env["CLOAK_UNSAFE_TEST_MODE"] = "1";
    process.env["CLOAK_SOCK"] = mock.path;
    const ipc = await import("../src/ipc.ts");
    ipc._resetForTests();
    await expect(ipc.request("vault.list", {})).rejects.toThrow(/denied.*policy says no/);
  });

  test("connect failure produces a clear error", async () => {
    process.env["CLOAK_UNSAFE_TEST_MODE"] = "1";
    process.env["CLOAK_SOCK"] = "/tmp/cloak-does-not-exist-" + Math.random().toString(36).slice(2) + ".sock";
    const ipc = await import("../src/ipc.ts");
    ipc._resetForTests();
    await expect(ipc.request("vault.list", {})).rejects.toThrow(/connect failed/);
  });

  test("socket path can be provided as an argv override", async () => {
    process.env["CLOAK_UNSAFE_TEST_MODE"] = "1";
    process.env["CLOAK_SOCK"] = "/tmp/env-cloak.sock";
    process.argv = [...originalArgv, "--socket", "/tmp/argv-cloak.sock"];

    const ipc = await import("../src/ipc.ts");

    expect(ipc.socketPath()).toBe("/tmp/argv-cloak.sock");
  });

  test("socket argv override supports equals form", async () => {
    process.env["CLOAK_UNSAFE_TEST_MODE"] = "1";
    process.argv = [...originalArgv, "--cloak-sock=/tmp/equals-cloak.sock"];

    const ipc = await import("../src/ipc.ts");

    expect(ipc.socketPath()).toBe("/tmp/equals-cloak.sock");
  });

  test("socket overrides are ignored outside unsafe test mode", async () => {
    process.env["CLOAK_SOCK"] = "/tmp/env-cloak.sock";
    process.argv = [...originalArgv, "--socket", "/tmp/argv-cloak.sock"];

    const ipc = await import("../src/ipc.ts");

    expect(ipc.socketPath()).not.toBe("/tmp/env-cloak.sock");
    expect(ipc.socketPath()).not.toBe("/tmp/argv-cloak.sock");
  });

  test("explicit unsafe flag allows socket argv override without env mode", async () => {
    process.argv = [
      ...originalArgv,
      "--unsafe-allow-socket-override",
      "--socket",
      "/tmp/argv-cloak.sock",
    ];

    const ipc = await import("../src/ipc.ts");

    expect(ipc.socketPath()).toBe("/tmp/argv-cloak.sock");
  });

  test("side-effecting daemon methods do not use the MCP-layer timeout", async () => {
    const ipc = await import("../src/ipc.ts");

    expect(ipc._requestTimeoutMsForTests("vault.list")).toBe(30_000);
    expect(ipc._requestTimeoutMsForTests("tool.proxy_http")).toBeNull();
    expect(ipc._requestTimeoutMsForTests("tool.mint_token")).toBeNull();
  });
});
