import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { statSync } from "node:fs";
import { handshake } from "./ipc.ts";

interface FirstRunResult {
  status: number | null;
  signal: NodeJS.Signals | null;
  error?: Error;
}

interface HandshakeWithFirstRunOptions {
  env?: NodeJS.ProcessEnv;
  handshakeFn?: () => Promise<void>;
  runFirstRunFn?: (scriptPath: string) => FirstRunResult;
}

function consumeFirstRunScript(env: NodeJS.ProcessEnv): string | null {
  const scriptPath = env["CLOAK_DXT_FIRST_RUN"];
  delete env["CLOAK_DXT_FIRST_RUN"];

  if (!scriptPath || scriptPath.trim().length === 0) {
    return null;
  }

  try {
    if (!statSync(scriptPath).isFile()) {
      return null;
    }
  } catch {
    return null;
  }

  return scriptPath;
}

function formatFirstRunFailure(result: FirstRunResult): string {
  if (result.error) {
    return result.error.message;
  }
  if (result.signal) {
    return `terminated by ${result.signal}`;
  }
  return `exited with status ${result.status ?? "unknown"}`;
}

function normalizeSpawnResult(result: SpawnSyncReturns<Buffer>): FirstRunResult {
  return {
    status: result.status,
    signal: result.signal,
    error: result.error,
  };
}

function runFirstRunScript(scriptPath: string): FirstRunResult {
  return normalizeSpawnResult(
    spawnSync("node", [scriptPath], {
      env: process.env,
      stdio: ["ignore", "ignore", "inherit"],
    }),
  );
}

export async function handshakeWithDxtFirstRun(
  options: HandshakeWithFirstRunOptions = {},
): Promise<void> {
  const env = options.env ?? process.env;
  const handshakeFn = options.handshakeFn ?? handshake;
  const runFirstRunFn = options.runFirstRunFn ?? runFirstRunScript;
  const firstRunScript = consumeFirstRunScript(env);

  try {
    await handshakeFn();
    return;
  } catch (initialError) {
    if (!firstRunScript) {
      throw initialError;
    }

    const result = runFirstRunFn(firstRunScript);
    if (result.status !== 0) {
      const initialMsg = initialError instanceof Error ? initialError.message : String(initialError);
      throw new Error(
        `cloak DXT first-run setup ${formatFirstRunFailure(result)} after daemon handshake failed: ${initialMsg}`,
      );
    }
  }

  await handshakeFn();
}

