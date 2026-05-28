import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { handshakeWithDxtFirstRun } from "../src/dxt-first-run.ts";

let tempDir: string | null = null;

function makeFirstRunScript(): string {
  tempDir = mkdtempSync(join(tmpdir(), "cloak-dxt-first-run-"));
  const scriptPath = join(tempDir, "first-run.js");
  writeFileSync(scriptPath, "process.exit(0);\n", "utf8");
  return scriptPath;
}

afterEach(() => {
  if (tempDir) {
    rmSync(tempDir, { recursive: true, force: true });
    tempDir = null;
  }
});

describe("dxt first-run handshake retry", () => {
  test("consumes CLOAK_DXT_FIRST_RUN before handshake and retries once after setup", async () => {
    const scriptPath = makeFirstRunScript();
    const env: NodeJS.ProcessEnv = { CLOAK_DXT_FIRST_RUN: scriptPath };
    let handshakes = 0;
    let firstRuns = 0;

    await handshakeWithDxtFirstRun({
      env,
      handshakeFn: async () => {
        handshakes++;
        expect(env["CLOAK_DXT_FIRST_RUN"]).toBeUndefined();
        if (handshakes === 1) {
          throw new Error("connect failed");
        }
      },
      runFirstRunFn: (path) => {
        firstRuns++;
        expect(path).toBe(scriptPath);
        return { status: 0, signal: null };
      },
    });

    expect(handshakes).toBe(2);
    expect(firstRuns).toBe(1);
  });

  test("does not run setup when the configured first-run script is absent", async () => {
    const env: NodeJS.ProcessEnv = { CLOAK_DXT_FIRST_RUN: join(tmpdir(), "missing-first-run.js") };
    let firstRuns = 0;

    await expect(
      handshakeWithDxtFirstRun({
        env,
        handshakeFn: async () => {
          throw new Error("connect failed");
        },
        runFirstRunFn: () => {
          firstRuns++;
          return { status: 0, signal: null };
        },
      }),
    ).rejects.toThrow(/connect failed/);

    expect(env["CLOAK_DXT_FIRST_RUN"]).toBeUndefined();
    expect(firstRuns).toBe(0);
  });

  test("does not retry handshake when first-run setup fails", async () => {
    const env: NodeJS.ProcessEnv = { CLOAK_DXT_FIRST_RUN: makeFirstRunScript() };
    let handshakes = 0;

    await expect(
      handshakeWithDxtFirstRun({
        env,
        handshakeFn: async () => {
          handshakes++;
          throw new Error("handshake failed");
        },
        runFirstRunFn: () => ({ status: 2, signal: null }),
      }),
    ).rejects.toThrow(/first-run setup exited with status 2/);

    expect(handshakes).toBe(1);
  });
});

