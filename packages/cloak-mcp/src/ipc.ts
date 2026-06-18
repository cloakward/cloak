// Length-prefixed JSON-over-Unix-domain-socket IPC client for cloakd.
//
// Wire format (frozen, must match cloakd):
//   <u32 little-endian length><JSON utf-8 body>
//   max body 4 MiB
//
// Allowed network primitives in this file: ONLY `node:net` (UDS).
// DO NOT add http, https, fetch, axios, undici, node-fetch, or got here
// or anywhere in src/. The grep gate (scripts/check-no-http.mjs) enforces this.

import { createConnection, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { argValue } from "./argv.ts";
import { findCloak } from "./trust.ts";

const MAX_FRAME_BYTES = 4 * 1024 * 1024; // 4 MiB
const REQUEST_TIMEOUT_MS = 30_000;
// The daemon must own completion for side-effecting calls. It has bounded
// execution for both paths (`reqwest` proxy timeout and STS timeout), so the
// MCP shim waits for the authoritative daemon outcome instead of returning an
// ambiguous client-side timeout that might trigger a duplicate retry.
const DAEMON_BOUNDED_SIDE_EFFECTING_METHODS = new Set(["tool.proxy_http", "tool.mint_token"]);

export interface IpcError {
  code: string;
  message: string;
}

interface PendingRequest {
  resolve: (value: unknown) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout> | null;
}

interface RequestBody {
  id: string;
  method: string;
  params: object;
  session_token?: string;
}

interface ResponseBody {
  id: string;
  result?: unknown;
  error?: IpcError;
}

let socket: Socket | null = null;
let connecting: Promise<Socket> | null = null;
let sessionToken: string | null = null;
const pending = new Map<string, PendingRequest>();
let recvBuffer = Buffer.alloc(0);
// Lazy daemon handshake: established on the first non-handshake request, not at
// startup, so the MCP server answers `initialize` immediately. Handshaking at
// startup ran a synchronous daemon status check that blocked the event loop and
// tripped strict clients (Codex times out MCP startup after 30s).
let sessionEnsured: Promise<void> | null = null;
let sessionInitializer: (() => Promise<void>) | null = null;

function socketOverridesAllowed(): boolean {
  return (
    process.env["CLOAK_UNSAFE_TEST_MODE"] === "1" ||
    process.argv.includes("--unsafe-allow-socket-override")
  );
}

function requestTimeoutMs(method: string): number | null {
  return DAEMON_BOUNDED_SIDE_EFFECTING_METHODS.has(method) ? null : REQUEST_TIMEOUT_MS;
}

export function socketPath(): string {
  if (socketOverridesAllowed()) {
    const socketArg = argValue(process.argv, ["--socket", "--cloak-sock"]);
    if (socketArg) {
      return socketArg;
    }
    if (process.env["CLOAK_SOCK"]) {
      return process.env["CLOAK_SOCK"];
    }
  }
  const runtimeDir = process.env["XDG_RUNTIME_DIR"];
  if (runtimeDir && runtimeDir.length > 0) {
    return `${runtimeDir}/cloakd.sock`;
  }
  // Fallback: tmpdir + uid
  const uid = typeof process.getuid === "function" ? process.getuid() : 0;
  return `${tmpdir()}/cloakd-${uid}.sock`;
}

function failAllPending(err: Error): void {
  for (const [, p] of pending) {
    if (p.timer) clearTimeout(p.timer);
    p.reject(err);
  }
  pending.clear();
}

// On socket loss (e.g. the daemon restarted), drop the cached session so the
// next request transparently re-handshakes instead of replaying a stale token
// that a freshly restarted daemon would reject. Without this the MCP process
// would stay broken until the client restarted it.
function resetSessionState(): void {
  sessionToken = null;
  sessionEnsured = null;
}

function verifyDaemonWithCli(): void {
  if (socketOverridesAllowed()) {
    return;
  }
  const cloak = findCloak();
  if (!cloak) {
    throw new Error("trusted cloak CLI not found; install Cloak before connecting to cloakd");
  }

  const result = spawnSync(cloak, ["daemon", "status"], {
    encoding: "utf8",
    timeout: 10_000,
    env: process.env,
  });
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || "daemon status check failed").trim();
    throw new Error(`cloakd identity check failed: ${detail}`);
  }
}

function onData(chunk: Buffer): void {
  recvBuffer = Buffer.concat([recvBuffer, chunk]);
  // Parse out as many frames as fit.
  while (recvBuffer.length >= 4) {
    const len = recvBuffer.readUInt32LE(0);
    if (len > MAX_FRAME_BYTES) {
      const err = new Error(
        `cloakd response frame too large: ${len} bytes (max ${MAX_FRAME_BYTES})`,
      );
      failAllPending(err);
      try {
        socket?.destroy(err);
      } catch {
        // ignore
      }
      socket = null;
      recvBuffer = Buffer.alloc(0);
      resetSessionState();
      return;
    }
    if (recvBuffer.length < 4 + len) {
      // wait for more data
      return;
    }
    const body = recvBuffer.subarray(4, 4 + len);
    recvBuffer = recvBuffer.subarray(4 + len);

    let parsed: ResponseBody;
    try {
      parsed = JSON.parse(body.toString("utf8")) as ResponseBody;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      // We can't correlate this to a request without an id; fail the oldest pending.
      const firstId = pending.keys().next().value;
      if (firstId !== undefined) {
        const p = pending.get(firstId);
        if (p) {
          pending.delete(firstId);
          if (p.timer) clearTimeout(p.timer);
          p.reject(new Error(`cloakd returned malformed JSON: ${msg}`));
        }
      }
      continue;
    }

    if (typeof parsed.id !== "string") {
      // unknown; ignore
      continue;
    }
    const p = pending.get(parsed.id);
    if (!p) {
      continue;
    }
    pending.delete(parsed.id);
    if (p.timer) clearTimeout(p.timer);
    if (parsed.error) {
      p.reject(
        new Error(`cloakd error [${parsed.error.code}]: ${parsed.error.message}`),
      );
    } else {
      p.resolve(parsed.result ?? {});
    }
  }
}

async function connectIpc(): Promise<Socket> {
  if (socket && !socket.destroyed) return socket;
  if (connecting) return connecting;
  const path = socketPath();
  try {
    verifyDaemonWithCli();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return Promise.reject(new Error(`cloakd connect refused at ${path}: ${msg}`));
  }
  connecting = new Promise<Socket>((resolve, reject) => {
    const s = createConnection(path);
    let settled = false;
    const onError = (err: Error): void => {
      if (settled) return;
      settled = true;
      connecting = null;
      reject(new Error(`cloakd connect failed at ${path}: ${err.message}`));
    };
    s.once("error", onError);
    s.once("connect", () => {
      if (settled) return;
      settled = true;
      s.removeListener("error", onError);
      s.on("data", onData);
      s.on("error", (err) => {
        failAllPending(new Error(`cloakd socket error: ${err.message}`));
        socket = null;
        recvBuffer = Buffer.alloc(0);
        resetSessionState();
      });
      s.on("close", () => {
        failAllPending(new Error("cloakd socket closed"));
        if (socket === s) socket = null;
        recvBuffer = Buffer.alloc(0);
        resetSessionState();
      });
      socket = s;
      connecting = null;
      resolve(s);
    });
  });
  return connecting;
}

function encodeFrame(obj: object): Buffer {
  const json = Buffer.from(JSON.stringify(obj), "utf8");
  if (json.length > MAX_FRAME_BYTES) {
    throw new Error(
      `outbound IPC frame too large: ${json.length} bytes (max ${MAX_FRAME_BYTES})`,
    );
  }
  const header = Buffer.alloc(4);
  header.writeUInt32LE(json.length, 0);
  return Buffer.concat([header, json]);
}

// Register what establishes the daemon session (plain handshake, or the
// DXT-aware handshake). Called lazily on the first tool request.
export function setSessionInitializer(fn: () => Promise<void>): void {
  sessionInitializer = fn;
}

async function ensureSession(): Promise<void> {
  if (sessionToken) return;
  if (!sessionEnsured) {
    const init = sessionInitializer ?? handshake;
    sessionEnsured = init().catch((err) => {
      sessionEnsured = null;
      throw err;
    });
  }
  await sessionEnsured;
}

export async function request(method: string, params: object): Promise<unknown> {
  // Establish the session on the first real request, never for the handshake
  // call itself (which would recurse).
  if (method !== "mcp.handshake") {
    await ensureSession();
  }
  const s = await connectIpc();
  const id = randomUUID();
  const body: RequestBody = { id, method, params };
  if (sessionToken && method !== "mcp.handshake") {
    body.session_token = sessionToken;
  }
  const frame = encodeFrame(body);
  return new Promise<unknown>((resolve, reject) => {
    const timeoutMs = requestTimeoutMs(method);
    const timer = timeoutMs === null ? null : setTimeout(() => {
      pending.delete(id);
      reject(new Error(`cloakd request timed out after ${timeoutMs}ms (method=${method})`));
    }, timeoutMs);
    pending.set(id, { resolve, reject, timer });
    s.write(frame, (err) => {
      if (err) {
        pending.delete(id);
        if (timer) clearTimeout(timer);
        reject(new Error(`cloakd write failed: ${err.message}`));
      }
    });
  });
}

export async function handshake(): Promise<void> {
  const result = (await request("mcp.handshake", {})) as { session_token?: unknown };
  if (typeof result?.session_token !== "string" || result.session_token.length === 0) {
    throw new Error("cloakd handshake did not return a session_token");
  }
  sessionToken = result.session_token;
}

export function _resetForTests(): void {
  // Test-only: clear state between mock-server scenarios.
  failAllPending(new Error("reset"));
  try {
    socket?.destroy();
  } catch {
    // ignore
  }
  socket = null;
  connecting = null;
  sessionToken = null;
  sessionEnsured = null;
  sessionInitializer = null;
  recvBuffer = Buffer.alloc(0);
}

export function _getSessionToken(): string | null {
  return sessionToken;
}

export function _requestTimeoutMsForTests(method: string): number | null {
  return requestTimeoutMs(method);
}
