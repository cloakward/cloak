import { afterEach, describe, expect, test } from "bun:test";
import {
  chmodSync,
  chownSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { handshakeWithDxtFirstRun } from "../src/dxt-first-run.ts";
import { findCloak, trustedExecutable } from "../src/trust.ts";

let tempDir: string | null = null;
let distArtifact: string | null = null;

const TEST_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(TEST_DIR, "../../..");
const FIRST_RUN_SCRIPT = join(REPO_ROOT, "packaging", "cloak-dxt", "server", "first-run.js");
const BUILD_DXT_SCRIPT = join(REPO_ROOT, "scripts", "build-dxt.sh");

function makeTempDir(prefix: string): string {
  const base = join(REPO_ROOT, "target", "cloak-mcp-tests");
  mkdirSync(base, { recursive: true });
  chmodSync(base, 0o700);
  return mkdtempSync(join(base, prefix));
}

function makeFirstRunScript(): string {
  tempDir = makeTempDir("first-run-");
  const scriptPath = join(tempDir, "first-run.js");
  writeFileSync(scriptPath, "process.exit(0);\n", "utf8");
  return scriptPath;
}

function makeExecutable(path: string, body: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, body, "utf8");
  chmodSync(path, 0o755);
}

function makeHomebrewLikeCloak(): string | null {
  if (process.platform !== "darwin" || typeof process.getuid !== "function") {
    return null;
  }
  tempDir = makeTempDir("homebrew-");
  const brewRoot = join(tempDir, "homebrew");
  const binDir = join(brewRoot, "bin");
  const cloakBin = join(binDir, "cloak");
  makeExecutable(cloakBin, "#!/bin/sh\nexit 0\n");
  try {
    chownSync(brewRoot, process.getuid(), 80);
    chownSync(binDir, process.getuid(), 80);
    chmodSync(brewRoot, 0o775);
    chmodSync(binDir, 0o775);
  } catch {
    return null;
  }
  return cloakBin;
}

afterEach(() => {
  if (tempDir) {
    rmSync(tempDir, { recursive: true, force: true });
    tempDir = null;
  }
  if (distArtifact) {
    rmSync(distArtifact, { force: true });
    distArtifact = null;
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
      vaultInitializedFn: async () => true,
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
    const env: NodeJS.ProcessEnv = { CLOAK_DXT_FIRST_RUN: join(REPO_ROOT, "target", "missing-first-run.js") };
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

  test("accepts first-run script path from argv for compiled DXT binaries", async () => {
    const scriptPath = makeFirstRunScript();
    const env: NodeJS.ProcessEnv = {};
    let handshakes = 0;
    let firstRuns = 0;

    await handshakeWithDxtFirstRun({
      env,
      argv: ["cloak-mcp", "--dxt-first-run", scriptPath],
      handshakeFn: async () => {
        handshakes++;
        if (handshakes === 1) {
          throw new Error("connect failed");
        }
      },
      vaultInitializedFn: async () => true,
      runFirstRunFn: (path) => {
        firstRuns++;
        expect(path).toBe(scriptPath);
        return { status: 0, signal: null };
      },
    });

    expect(handshakes).toBe(2);
    expect(firstRuns).toBe(1);
  });

  test("shows setup guidance when daemon is reachable but vault is uninitialized", async () => {
    const scriptPath = makeFirstRunScript();
    const env: NodeJS.ProcessEnv = { CLOAK_DXT_FIRST_RUN: scriptPath };
    let firstRuns = 0;

    await expect(
      handshakeWithDxtFirstRun({
        env,
        handshakeFn: async () => {},
        vaultInitializedFn: async () => false,
        runFirstRunFn: (path) => {
          firstRuns++;
          expect(path).toBe(scriptPath);
          return { status: 2, signal: null };
        },
      }),
    ).rejects.toThrow(/terminal setup required/);

    expect(firstRuns).toBe(1);
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

describe("dxt first-run setup script", () => {
  test("does not run setup from the extension host", () => {
    tempDir = makeTempDir("script-");
    const home = join(tempDir, "home");
    const binDir = join(tempDir, "bin");
    const logPath = join(tempDir, "cloak.log");
    const cloakBin = join(binDir, "cloak");
    const marker = join(home, ".config", "cloak", ".dxt-setup-complete");

    mkdirSync(dirname(marker), { recursive: true });
    writeFileSync(marker, "stale\n", { encoding: "utf8", flag: "w" });
    makeExecutable(
      cloakBin,
      "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CLOAK_TEST_LOG\"\nexit 0\n",
    );

    const result = spawnSync(process.execPath, [FIRST_RUN_SCRIPT], {
      env: {
        ...process.env,
        HOME: home,
        CLOAK_CLI: cloakBin,
        CLOAK_TEST_LOG: logPath,
        CLOAK_DXT_SUPPRESS_DIALOGS: "1",
        PATH: "",
      },
      encoding: "utf8",
    });

    expect(result.status).toBe(2);
    expect(existsSync(logPath)).toBe(false);
    expect(existsSync(marker)).toBe(true);
    expect(readFileSync(marker, "utf8")).toBe("stale\n");
    expect(result.stderr).toContain("terminal setup required");
    expect(result.stderr).toContain(realpathSync(cloakBin));
  });

  test("terminal setup prompt resolves explicit trusted cloak path before PATH fallback", () => {
    tempDir = makeTempDir("script-");
    const home = join(tempDir, "home");
    const trustedDir = join(tempDir, "trusted");
    const pathDir = join(tempDir, "path-bin");
    const trustedLog = join(tempDir, "trusted.log");
    const pathLog = join(tempDir, "path.log");
    const trustedCloak = join(trustedDir, "cloak");
    const pathCloak = join(pathDir, "cloak");

    makeExecutable(
      trustedCloak,
      "#!/bin/sh\nprintf 'trusted %s\\n' \"$*\" > \"$CLOAK_TRUSTED_LOG\"\nexit 0\n",
    );
    makeExecutable(
      pathCloak,
      "#!/bin/sh\nprintf 'path %s\\n' \"$*\" > \"$CLOAK_PATH_LOG\"\nexit 42\n",
    );

    const result = spawnSync(process.execPath, [FIRST_RUN_SCRIPT], {
      env: {
        ...process.env,
        HOME: home,
        CLOAK_CLI: trustedCloak,
        CLOAK_TRUSTED_LOG: trustedLog,
        CLOAK_PATH_LOG: pathLog,
        CLOAK_DXT_SUPPRESS_DIALOGS: "1",
        PATH: pathDir,
      },
      encoding: "utf8",
    });

    expect(result.status).toBe(2);
    expect(result.stderr).toContain(realpathSync(trustedCloak));
    expect(existsSync(trustedLog)).toBe(false);
    expect(existsSync(pathLog)).toBe(false);
  });

  test("trust allows macOS Homebrew admin-group writable parent dirs", () => {
    const cloakBin = makeHomebrewLikeCloak();
    if (!cloakBin) return;

    expect(trustedExecutable(cloakBin)).toBe(realpathSync(cloakBin));
    expect(findCloak({ CLOAK_CLI: cloakBin, PATH: "" })).toBe(realpathSync(cloakBin));

    const result = spawnSync(process.execPath, [FIRST_RUN_SCRIPT], {
      env: {
        ...process.env,
        CLOAK_CLI: cloakBin,
        CLOAK_DXT_SUPPRESS_DIALOGS: "1",
        PATH: "",
      },
      encoding: "utf8",
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toContain(realpathSync(cloakBin));
    expect(result.stderr).not.toContain("CLI is not installed");
  });

  test("finds trusted cloak sibling next to the running cloak-mcp binary", () => {
    tempDir = makeTempDir("sibling-");
    const binDir = join(tempDir, "bin");
    const cloakBin = join(binDir, "cloak");
    const mcpBin = join(binDir, "cloak-mcp");

    makeExecutable(cloakBin, "#!/bin/sh\nexit 0\n");
    makeExecutable(mcpBin, "#!/bin/sh\nexit 0\n");

    expect(findCloak({ PATH: "" }, [mcpBin])).toBe(realpathSync(cloakBin));
  });

  test("prefers sibling cloak over explicit fallback paths", () => {
    tempDir = makeTempDir("sibling-precedence-");
    const binDir = join(tempDir, "bin");
    const otherDir = join(tempDir, "other-bin");
    const siblingCloak = join(binDir, "cloak");
    const mcpBin = join(binDir, "cloak-mcp");
    const fallbackCloak = join(otherDir, "cloak");

    makeExecutable(siblingCloak, "#!/bin/sh\nexit 0\n");
    makeExecutable(mcpBin, "#!/bin/sh\nexit 0\n");
    makeExecutable(fallbackCloak, "#!/bin/sh\nexit 0\n");

    expect(
      findCloak(
        {
          CLOAK_CLI: fallbackCloak,
          PATH: otherDir,
        },
        [mcpBin],
      ),
    ).toBe(realpathSync(siblingCloak));
  });

});

describe("dxt build packaging", () => {
  test("rewrites the staged manifest version without editing the source manifest", () => {
    tempDir = makeTempDir("build-");
    const fakeMcp = join(tempDir, "cloak-mcp");

    const version = `9.9.9-test.${process.pid}`;
    makeExecutable(fakeMcp, `#!/bin/sh\nprintf 'cloak-mcp ${version}\\n'\nexit 0\n`);

    const platform = "macos-x64";
    distArtifact = join(REPO_ROOT, "dist", `Cloak-${version}-${platform}.dxt`);
    const manifestPath = join(REPO_ROOT, "packaging", "cloak-dxt", "manifest.json");
    const sourceVersion = JSON.parse(readFileSync(manifestPath, "utf8")).version;

    const build = spawnSync("bash", [BUILD_DXT_SCRIPT, version, platform, fakeMcp], {
      cwd: REPO_ROOT,
      encoding: "utf8",
    });
    expect(build.status).toBe(0);

    const unzip = spawnSync("unzip", ["-p", distArtifact, "manifest.json"], {
      cwd: REPO_ROOT,
      encoding: "utf8",
    });
    expect(unzip.status).toBe(0);
    const manifest = JSON.parse(unzip.stdout);
    expect(manifest.version).toBe(version);
    expect(manifest.manifest_version).toBe("0.3");
    expect(manifest.mcpb_version).toBeUndefined();
    expect(manifest.server.mcp_config.platforms).toBeUndefined();
    expect(manifest.privacy_policies).toContain(
      `https://github.com/cloakward/cloak/blob/v${version}/docs/PRIVACY.md`,
    );
    expect(manifest.compatibility.platforms).toEqual(["darwin"]);
    expect(manifest.server.mcp_config.platform_overrides.linux).toBeUndefined();
    expect(manifest.server.mcp_config.platform_overrides.darwin.command).toBe(
      "${__dirname}/server/binaries/cloak-mcp",
    );
    expect(JSON.parse(readFileSync(manifestPath, "utf8")).version).toBe(sourceVersion);
  });

  test("accepts prevalidated version output for cross-OS DXT packaging", () => {
    tempDir = makeTempDir("build-cross-");
    const fakeMcp = join(tempDir, "cloak-mcp");

    const version = `9.9.9-cross.${process.pid}`;
    makeExecutable(fakeMcp, "#!/bin/sh\necho 'wrong host cannot execute this in release'\nexit 99\n");

    const platform = "macos-arm64";
    distArtifact = join(REPO_ROOT, "dist", `Cloak-${version}-${platform}.dxt`);

    const build = spawnSync(
      "bash",
      [BUILD_DXT_SCRIPT, version, platform, fakeMcp, `cloak-mcp ${version}`],
      {
        cwd: REPO_ROOT,
        encoding: "utf8",
      },
    );
    expect(build.status).toBe(0);
    expect(readFileSync(distArtifact).byteLength).toBeGreaterThan(0);

    const unzip = spawnSync("unzip", ["-p", distArtifact, "manifest.json"], {
      cwd: REPO_ROOT,
      encoding: "utf8",
    });
    expect(unzip.status).toBe(0);
    const manifest = JSON.parse(unzip.stdout);
    expect(manifest.compatibility.platforms).toEqual(["darwin"]);
    expect(manifest.server.mcp_config.platform_overrides.darwin.command).toBe(
      "${__dirname}/server/binaries/cloak-mcp",
    );
    expect(manifest.server.mcp_config.platform_overrides.linux).toBeUndefined();
  });

  test("rejects Linux DXT packaging because Claude Desktop MCPB is not a Linux install surface", () => {
    tempDir = makeTempDir("build-linux-");
    const fakeMcp = join(tempDir, "cloak-mcp");

    makeExecutable(fakeMcp, "#!/bin/sh\nprintf 'cloak-mcp 9.9.9\\n'\nexit 0\n");

    const build = spawnSync(
      "bash",
      [BUILD_DXT_SCRIPT, "9.9.9", "linux-x64", fakeMcp, "cloak-mcp 9.9.9"],
      {
        cwd: REPO_ROOT,
        encoding: "utf8",
      },
    );
    expect(build.status).toBe(2);
    expect(build.stderr).toContain("unsupported DXT platform tag");
  });
});
