/**
 * Transports for the release interface.
 *
 *  - InProcessReleaser: calls a verifier directly (tests, single-process dev). The request is
 *    round-tripped through JSON so nothing but plain data crosses, exactly as on a socket.
 *  - SocketReleaser / pushSecrets / serveVerifier: one length-prefixed JSON frame each way over a stream
 *    socket (a Unix socket path or host:port). Node has no AF_VSOCK, so in production each side
 *    bridges to vsock with socat (see docs/ENCLAVE.md); the framing is unchanged.
 */
import * as net from "node:net";
import {
  MAX_FRAME_BYTES,
  type KeyReleaser,
  type ReleaseRequest,
  type ReleaseResponse,
  type SecretsMessage,
  type SecretsResponse,
} from "./protocol.js";
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

/** Send one frame, read one frame back. */
async function exchange(target: SocketTarget, msg: unknown, timeoutMs: number): Promise<unknown> {
  const sock = "path" in target ? net.createConnection(target.path) : net.createConnection(target.port, target.host);
  try {
    await new Promise<void>((resolve, reject) => {
      sock.once("connect", resolve);
      sock.once("error", reject);
    });
    const reply = readFrame(sock, timeoutMs);
    sock.write(frame(msg));
    return await reply;
  } finally {
    sock.destroy();
  }
}

export class SocketReleaser implements KeyReleaser {
  constructor(
    private readonly target: SocketTarget,
    private readonly timeoutMs = 30_000,
  ) {}

  async release(req: ReleaseRequest): Promise<ReleaseResponse> {
    return (await exchange(this.target, req, this.timeoutMs)) as ReleaseResponse;
  }
}

/** Parent side: deliver credentials / API keys to the verifier over the same channel. */
export async function pushSecrets(target: SocketTarget, msg: SecretsMessage, timeoutMs = 10_000): Promise<SecretsResponse> {
  return (await exchange(target, msg, timeoutMs)) as SecretsResponse;
}

/** Serve a verifier: one message per connection (a release request or a secrets delivery). */
export async function serveVerifier(verifier: KeyReleaseVerifier, target: SocketTarget): Promise<net.Server> {
  const server = net.createServer((sock) => {
    readFrame(sock, 30_000)
      .then((req) => verifier.handle(req))
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
