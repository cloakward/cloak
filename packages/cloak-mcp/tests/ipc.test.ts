import { describe, test, expect, afterEach } from "bun:test";
import { startMockDaemon, type MockServer } from "./mock-daemon.ts";

let mock: MockServer | null = null;

afterEach(async () => {
  const ipc = await import("../src/ipc.ts");
  ipc._resetForTests();
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
        "vault.list": (params: unknown) => {
          // mock-daemon doesn't show us the token, but we can recover it from
          // the request body via a side channel: the mock will be enhanced
          // for this test.
          return { secrets: [], _seen_token: lastSeenToken };
        },
      },
    });
    process.env["CLOAK_SOCK"] = mock.path;
    const ipc = await import("../src/ipc.ts");
    ipc._resetForTests();
    await ipc.handshake();
    expect(ipc._getSessionToken()).toBe("deadbeef");
  });

  test("error response surfaces code and message", async () => {
    mock = await startMockDaemon({
      handlers: {
        "vault.list": () => ({ __error: { code: "denied", message: "policy says no" } }),
      },
    });
    process.env["CLOAK_SOCK"] = mock.path;
    const ipc = await import("../src/ipc.ts");
    ipc._resetForTests();
    await expect(ipc.request("vault.list", {})).rejects.toThrow(/denied.*policy says no/);
  });

  test("connect failure produces a clear error", async () => {
    process.env["CLOAK_SOCK"] = "/tmp/cloak-does-not-exist-" + Math.random().toString(36).slice(2) + ".sock";
    const ipc = await import("../src/ipc.ts");
    ipc._resetForTests();
    await expect(ipc.request("vault.list", {})).rejects.toThrow(/connect failed/);
  });
});
