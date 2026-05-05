import { describe, test, expect } from "bun:test";
import { spawnSync } from "node:child_process";
import { join } from "node:path";

describe("lint:no-http", () => {
  test("scripts/check-no-http.mjs passes against current src/", () => {
    const root = join(import.meta.dir, "..");
    const result = spawnSync("node", ["scripts/check-no-http.mjs"], {
      cwd: root,
      encoding: "utf8",
    });
    if (result.status !== 0) {
      // surface the output for easier diagnosis
      console.error(result.stdout);
      console.error(result.stderr);
    }
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("ok");
  });
});
