// Self-test: connect to cloakd, handshake, list vault. Prints "ok" on success.
// Exits 0 on success, 2 on failure. Used by `--self-test` flag and CI smoke checks.

import { handshake, request } from "./ipc.ts";

export async function runSelfTest(): Promise<void> {
  await handshake();
  await request("vault.list", {});
  // Stdout is fine here — self-test is not used over MCP framing.
  process.stdout.write("ok\n");
}

if (import.meta.main) {
  runSelfTest().then(
    () => process.exit(0),
    (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`self-test failed: ${msg}\n`);
      process.exit(2);
    },
  );
}
