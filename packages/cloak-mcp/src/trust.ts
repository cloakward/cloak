import {
  accessSync,
  constants,
  realpathSync,
  statSync,
} from "node:fs";
import path from "node:path";

export const CLOAK_EXE = process.platform === "win32" ? "cloak.exe" : "cloak";
export const CLOAK_MCP_EXE = process.platform === "win32" ? "cloak-mcp.exe" : "cloak-mcp";

export function currentUid(): number | null {
  return typeof process.getuid === "function" ? process.getuid() : null;
}

function currentGroups(): number[] {
  return typeof process.getgroups === "function" ? process.getgroups() : [];
}

function trustedExecutableMode(mode: number): boolean {
  return (mode & 0o022) === 0;
}

function trustedDirectoryMode(mode: number, gid: number): boolean {
  if ((mode & 0o002) !== 0) return false;
  if ((mode & 0o020) === 0) return true;

  // Apple Silicon Homebrew normally lives under /opt/homebrew with
  // admin-group-writable directories. That is the documented install path, so
  // accept that specific macOS group while still rejecting world-writable dirs
  // and group-writable dirs owned by broad groups like staff.
  return process.platform === "darwin" && gid === 80 && currentGroups().includes(gid);
}

export function trustedExecutable(file: string | undefined): string | null {
  if (!file || !path.isAbsolute(file)) return null;
  try {
    const resolved = realpathSync(file);
    const st = statSync(resolved);
    if (!st.isFile()) return null;
    accessSync(resolved, constants.X_OK);

    const uid = currentUid();
    if (uid !== null && st.uid !== 0 && st.uid !== uid) return null;
    if (!trustedExecutableMode(st.mode)) return null;

    let dir = path.dirname(resolved);
    while (true) {
      const dst = statSync(dir);
      if (uid !== null && dst.uid !== 0 && dst.uid !== uid) return null;
      if (!trustedDirectoryMode(dst.mode, dst.gid)) return null;
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
    return resolved;
  } catch {
    return null;
  }
}

export function findOnPath(bin: string, env: NodeJS.ProcessEnv = process.env): string | null {
  for (const dir of (env["PATH"] || "").split(path.delimiter)) {
    if (!dir || !path.isAbsolute(dir)) continue;
    const candidate = trustedExecutable(path.join(dir, bin));
    if (candidate) return candidate;
  }
  return null;
}

function trustedCloakCandidates(
  env: NodeJS.ProcessEnv = process.env,
  executablePaths: Array<string | undefined> = [process.execPath, process.argv[1]],
): string[] {
  const siblingCandidates: string[] = [];
  for (const executable of executablePaths) {
    if (executable && path.isAbsolute(executable)) {
      siblingCandidates.push(path.join(path.dirname(executable), CLOAK_EXE));
    }
  }

  const candidates = [
    ...siblingCandidates,
    env["CLOAK_CLI"],
    ...(env["CLOAK_DXT_CLOAK_PATHS"] || "").split(path.delimiter),
    "/opt/homebrew/bin/cloak",
    "/usr/local/bin/cloak",
    "/usr/bin/cloak",
    "/bin/cloak",
    "/opt/cloak/bin/cloak",
  ].filter((value): value is string => Boolean(value));

  return candidates.filter((value, index, all) => all.indexOf(value) === index);
}

export function findCloak(
  env: NodeJS.ProcessEnv = process.env,
  executablePaths?: Array<string | undefined>,
): string | null {
  for (const candidate of trustedCloakCandidates(env, executablePaths)) {
    const trusted = trustedExecutable(candidate);
    if (trusted) return trusted;
  }
  return findOnPath(CLOAK_EXE, env);
}
