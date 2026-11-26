/**
 * Outbound connections from the verifier. The enclave has no network card: its only way out is
 * vsock to the parent instance, which forwards raw bytes to a fixed host (AWS's vsock-proxy, one
 * port per allowlisted host). TLS runs inside the verifier (src/egress/https.ts), so the parent
 * only ever relays ciphertext and can't read or forge a response.
 *
 * A Dialer turns "host:port" into a raw byte stream:
 *  - RoutedDialer: an allowlist mapping each remote host to a local port or socket. In the
 *    enclave each local port is socat → vsock(3:port) → parent vsock-proxy → host:443.
 *  - DirectDialer: plain TCP, for local development and the optional live tests.
 */
import * as net from "node:net";
import type { Duplex } from "node:stream";

export interface Dialer {
  dial(host: string, port: number): Promise<Duplex>;
}

export type LocalTarget = { path: string } | { host: string; port: number };

export class EgressRefusedError extends Error {
  override name = "EgressRefusedError";
}

function connect(target: LocalTarget, timeoutMs: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const sock = "path" in target ? net.createConnection(target.path) : net.createConnection(target.port, target.host);
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error("egress connect timed out"));
    }, timeoutMs);
    sock.once("connect", () => {
      clearTimeout(timer);
      resolve(sock);
    });
    sock.once("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

export class RoutedDialer implements Dialer {
  private readonly routes: Map<string, LocalTarget>;

  /** routes: { "kms.us-east-1.amazonaws.com:443": { host: "127.0.0.1", port: 8000 }, ... } */
  constructor(
    routes: Record<string, LocalTarget>,
    private readonly timeoutMs = 10_000,
  ) {
    this.routes = new Map(Object.entries(routes).map(([k, v]) => [k.toLowerCase(), v]));
  }

  async dial(host: string, port: number): Promise<Duplex> {
    const target = this.routes.get(`${host.toLowerCase()}:${port}`);
    if (!target) throw new EgressRefusedError(`no egress route for ${host}:${port}`);
    return connect(target, this.timeoutMs);
  }

  get hosts(): string[] {
    return [...this.routes.keys()];
  }
}

/**
 * Parse EGRESS_ROUTES: "kms.us-east-1.amazonaws.com:443=127.0.0.1:8000,www.thesportsdb.com:443=127.0.0.1:8002".
 * The port on the left defaults to 443; the right side is host:port or a Unix socket path.
 */
export function parseRoutes(spec: string): Record<string, LocalTarget> {
  const out: Record<string, LocalTarget> = {};
  for (const part of spec.split(",").map((s) => s.trim()).filter(Boolean)) {
    const m = /^([A-Za-z0-9.-]+)(?::(\d+))?=(.+)$/.exec(part);
    if (!m) throw new Error(`bad EGRESS_ROUTES entry ${JSON.stringify(part)}`);
    const remote = `${m[1]}:${m[2] ?? "443"}`;
    const local = m[3]!;
    const hp = /^([^:/]+):(\d+)$/.exec(local);
    out[remote] = hp ? { host: hp[1]!, port: Number(hp[2]) } : { path: local };
  }
  return out;
}

export class DirectDialer implements Dialer {
  constructor(private readonly timeoutMs = 10_000) {}
  dial(host: string, port: number): Promise<Duplex> {
    return connect({ host, port }, this.timeoutMs);
  }
}
