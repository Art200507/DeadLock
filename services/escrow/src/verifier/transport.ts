/**
 * Transports for the release interface.
 *
 *  - InProcessReleaser: calls a verifier directly (tests, single-process dev). The request is
 *    round-tripped through JSON so nothing but plain data crosses, exactly as on a socket.
 *  - SocketReleaser / serveVerifier: one length-prefixed JSON frame each way over a stream
 *    socket (a Unix socket path or host:port). Node has no AF_VSOCK, so in production each side
 *    bridges to vsock with socat (see docs/ENCLAVE.md); the framing is unchanged.
 */
import * as net from "node:net";
import { MAX_FRAME_BYTES, type KeyReleaser, type ReleaseRequest, type ReleaseResponse } from "./protocol.js";
import type { KeyReleaseVerifier } from "./verifier.js";

export type SocketTarget = { path: string } | { host: string; port: number };

export class InProcessReleaser implements KeyReleaser {
  constructor(private readonly verifier: KeyReleaseVerifier) {}
  async release(req: ReleaseRequest): Promise<ReleaseResponse> {
    const res = await this.verifier.release(JSON.parse(JSON.stringify(req)));
    return JSON.parse(JSON.stringify(res)) as ReleaseResponse;
  }
}

function frame(obj: unknown): Buffer {
  const body = Buffer.from(JSON.stringify(obj));
  if (body.length > MAX_FRAME_BYTES) throw new Error("frame too large");
  const len = Buffer.alloc(4);
  len.writeUInt32BE(body.length);
  return Buffer.concat([len, body]);
}

/** Read exactly one frame from a socket. */
function readFrame(sock: net.Socket, timeoutMs: number): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => done(new Error("timed out")), timeoutMs);
    const done = (err: Error | null, value?: unknown) => {
      clearTimeout(timer);
      sock.off("data", onData);
      sock.off("error", onErr);
      sock.off("end", onEnd);
      if (err) reject(err);
      else resolve(value);
    };
    const onData = (d: Buffer) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= 4) {
        const n = buf.readUInt32BE(0);
        if (n > MAX_FRAME_BYTES) return done(new Error("frame too large"));
        if (buf.length >= 4 + n) {
          try {
            done(null, JSON.parse(buf.subarray(4, 4 + n).toString("utf8")));
          } catch {
            done(new Error("frame is not JSON"));
          }
        }
      }
    };
    const onErr = (e: Error) => done(e);
    const onEnd = () => done(new Error("connection closed before a full frame"));
    sock.on("data", onData);
    sock.on("error", onErr);
    sock.on("end", onEnd);
  });
}

export class SocketReleaser implements KeyReleaser {
  constructor(
    private readonly target: SocketTarget,
    private readonly timeoutMs = 15_000,
  ) {}

  async release(req: ReleaseRequest): Promise<ReleaseResponse> {
    const sock = "path" in this.target ? net.createConnection(this.target.path) : net.createConnection(this.target.port, this.target.host);
    try {
      await new Promise<void>((resolve, reject) => {
        sock.once("connect", resolve);
        sock.once("error", reject);
      });
      const reply = readFrame(sock, this.timeoutMs);
      sock.write(frame(req));
      return (await reply) as ReleaseResponse;
    } finally {
      sock.destroy();
    }
  }
}

/** Serve a verifier: one request per connection. */
export async function serveVerifier(verifier: KeyReleaseVerifier, target: SocketTarget): Promise<net.Server> {
  const server = net.createServer((sock) => {
    readFrame(sock, 15_000)
      .then((req) => verifier.release(req))
      .then(
        (res) => sock.end(frame(res)),
        () => sock.destroy(),
      );
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    if ("path" in target) server.listen(target.path, resolve);
    else server.listen(target.port, target.host, resolve);
  });
  return server;
}
