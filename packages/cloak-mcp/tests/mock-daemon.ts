// In-process mock cloakd. Listens on a temp UDS path and replies to
// requests using a method handler map. Returns the path so tests can
// set CLOAK_SOCK before importing src/ipc.ts.

import { createServer, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { unlinkSync } from "node:fs";

export type Handler = (params: unknown) => unknown | Promise<unknown>;
export interface MockOptions {
  // Override what is sent back. If returned value is { __error: {code,message} },
  // the mock will respond with an error frame.
  handlers: Record<string, Handler>;
  // If true, server intentionally responds with an oversized length header
  // (for the oversized-frame test).
  oversize?: boolean;
  // If true, server responds with malformed JSON for the next request.
  malformedJson?: boolean;
}

export interface MockServer {
  path: string;
  close: () => Promise<void>;
}

export async function startMockDaemon(opts: MockOptions): Promise<MockServer> {
  const path = join(
    tmpdir(),
    `cloak-mock-${process.pid}-${Math.random().toString(36).slice(2)}.sock`,
  );
  try {
    unlinkSync(path);
  } catch {
    // not present, fine
  }

  const clients = new Set<Socket>();
  const server: Server = createServer((sock: Socket) => {
    clients.add(sock);
    sock.once("close", () => clients.delete(sock));
    let buf = Buffer.alloc(0);
    sock.on("data", async (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      while (buf.length >= 4) {
        const len = buf.readUInt32LE(0);
        if (buf.length < 4 + len) return;
        const body = buf.subarray(4, 4 + len).toString("utf8");
        buf = buf.subarray(4 + len);
        let req: { id: string; method: string; params: unknown };
        try {
          req = JSON.parse(body);
        } catch {
          continue;
        }
        const handler = opts.handlers[req.method];
        let respBody: object;
        if (!handler) {
          respBody = {
            id: req.id,
            error: { code: "method_not_found", message: `unknown method: ${req.method}` },
          };
        } else {
          try {
            const out = await handler(req.params);
            if (
              out &&
              typeof out === "object" &&
              "__error" in (out as Record<string, unknown>)
            ) {
              const e = (out as { __error: { code: string; message: string } }).__error;
              respBody = { id: req.id, error: e };
            } else {
              respBody = { id: req.id, result: out };
            }
          } catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            respBody = { id: req.id, error: { code: "internal", message: msg } };
          }
        }

        if (opts.malformedJson) {
          opts.malformedJson = false;
          const garbage = Buffer.from("{not-json", "utf8");
          const header = Buffer.alloc(4);
          header.writeUInt32LE(garbage.length, 0);
          sock.write(Buffer.concat([header, garbage]));
          continue;
        }

        const json = Buffer.from(JSON.stringify(respBody), "utf8");
        if (opts.oversize) {
          opts.oversize = false;
          // Lie about length — claim 5 MiB so client rejects.
          const header = Buffer.alloc(4);
          header.writeUInt32LE(5 * 1024 * 1024, 0);
          sock.write(Buffer.concat([header, json]));
          continue;
        }
        const header = Buffer.alloc(4);
        header.writeUInt32LE(json.length, 0);
        sock.write(Buffer.concat([header, json]));
      }
    });
    sock.on("error", () => {
      // ignore
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(path, () => {
      server.removeListener("error", reject);
      resolve();
    });
  });

  return {
    path,
    close: () =>
      new Promise<void>((resolve) => {
        // Forcibly tear down any in-flight client sockets so server.close()
        // doesn't wait on them.
        for (const c of clients) {
          try {
            c.destroy();
          } catch {
            // ignore
          }
        }
        clients.clear();
        server.close(() => {
          try {
            unlinkSync(path);
          } catch {
            // ignore
          }
          resolve();
        });
      }),
  };
}
