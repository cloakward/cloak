import { spawnSync } from "node:child_process";
import { statSync } from "node:fs";
import { handshake, request } from "./ipc.ts";
import { argValue } from "./argv.ts";
import { findCloak, findOnPath, trustedExecutable } from "./trust.ts";

interface FirstRunResult {
  status: number | null;
  signal: NodeJS.Signals | null;
  error?: Error;
}

interface HandshakeWithFirstRunOptions {
  env?: NodeJS.ProcessEnv;
  argv?: string[];
  handshakeFn?: () => Promise<void>;
  vaultInitializedFn?: () => Promise<boolean>;
  runFirstRunFn?: (scriptPath: string) => FirstRunResult;
}

function consumeFirstRunScript(env: NodeJS.ProcessEnv, argv: string[]): string | null {
  const scriptPath =
    argValue(argv, ["--dxt-first-run", "--cloak-dxt-first-run"]) ??
    env["CLOAK_DXT_FIRST_RUN"];
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

const INSTALL_URL = "https://github.com/cloakward/cloak#install";

function nativeDialog(title: string, message: string): void {
  if (process.env["CLOAK_DXT_SUPPRESS_DIALOGS"] === "1") {
    process.stderr.write(`[${title}] ${message}\n`);
    return;
  }
  if (process.platform === "darwin") {
    const osascript = trustedExecutable("/usr/bin/osascript");
    if (osascript) {
      const script = `display dialog ${JSON.stringify(message)} with title ${JSON.stringify(title)} buttons {"OK"} default button "OK"`;
      spawnSync(osascript, ["-e", script], { stdio: "ignore" });
      return;
    }
  }
  if (process.platform === "linux") {
    for (const tool of ["zenity", "kdialog", "notify-send"]) {
      const dialogTool = findOnPath(tool);
      if (!dialogTool) continue;
      if (tool === "zenity") {
        spawnSync(dialogTool, ["--info", `--title=${title}`, `--text=${message}`], { stdio: "ignore" });
        return;
      }
      if (tool === "kdialog") {
        spawnSync(dialogTool, ["--title", title, "--msgbox", message], { stdio: "ignore" });
        return;
      }
      spawnSync(dialogTool, [title, message], { stdio: "ignore" });
      return;
    }
  }
  process.stderr.write(`[${title}] ${message}\n`);
}

function runFirstRunScript(scriptPath: string): FirstRunResult {
  const cloakBin = findCloak();
  if (!cloakBin) {
    nativeDialog(
      "Cloak: install required",
      `Cloak's CLI is not installed.\n\nInstall it from ${INSTALL_URL}, then restart Claude Desktop.`,
    );
    return { status: 2, signal: null };
  }

  nativeDialog(
    "Cloak: terminal setup required",
    `Cloak is installed at ${cloakBin}, but the extension cannot safely initialize a vault because the one-time recovery seed must be shown in a terminal.\n\nOpen a terminal, run \`cloak setup\`, write down and verify the recovery seed, then run \`cloak daemon start\` and \`cloak unlock\`. Restart Claude Desktop after the daemon is running and unlocked.`,
  );
  void scriptPath;
  return { status: 2, signal: null };
}

export async function handshakeWithDxtFirstRun(
  options: HandshakeWithFirstRunOptions = {},
): Promise<void> {
  const env = options.env ?? process.env;
  const argv = options.argv ?? process.argv;
  const handshakeFn = options.handshakeFn ?? handshake;
  const vaultInitializedFn = options.vaultInitializedFn ?? vaultInitialized;
  const runFirstRunFn = options.runFirstRunFn ?? runFirstRunScript;
  const firstRunScript = consumeFirstRunScript(env, argv);

  let completedHandshake = false;
  try {
    await handshakeFn();
    completedHandshake = true;
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

  if (!completedHandshake) {
    await handshakeFn();
    completedHandshake = true;
  }
  if (firstRunScript) {
    await ensureVaultInitializedForDxt(vaultInitializedFn, runFirstRunFn, firstRunScript);
  }
}

async function vaultInitialized(): Promise<boolean> {
  const result = (await request("vault.is_initialized", {})) as { initialized?: unknown };
  return result.initialized === true;
}

async function ensureVaultInitializedForDxt(
  vaultInitializedFn: () => Promise<boolean>,
  runFirstRunFn: (scriptPath: string) => FirstRunResult,
  firstRunScript: string,
): Promise<void> {
  if (await vaultInitializedFn()) {
    return;
  }
  const result = runFirstRunFn(firstRunScript);
  if (result.status !== 0) {
    throw new Error(
      `cloak DXT terminal setup required: ${formatFirstRunFailure(result)}`,
    );
  }
  if (!(await vaultInitializedFn())) {
    throw new Error("cloak DXT terminal setup did not initialize the vault");
  }
}
