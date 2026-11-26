/**
 * HTTPS with TLS terminated inside the verifier, over whatever byte stream a Dialer provides.
 *
 * Certificates are checked against a pinned CA bundle: by default Node's built-in Mozilla roots,
 * which are part of the enclave image and so part of PCR0. The parent that relays the bytes
 * can't present a valid certificate for api-sports.io, thesportsdb.com or kms.*.amazonaws.com,
 * so it can't read requests (API keys, AWS signatures) or forge responses (scores, KMS replies).
 *
 * `agent` is an https.Agent, so the same path serves the AWS SDK (via NodeHttpHandler) and our
 * own JSON fetches.
 */
import * as http from "node:http";
import * as https from "node:https";
import * as tls from "node:tls";
import type { Duplex } from "node:stream";
import type { Dialer } from "./dialer.js";

export const MAX_RESPONSE_BYTES = 1024 * 1024;

export interface EgressHttpsOptions {
  dialer: Dialer;
  /** PEM CA certificates to trust. Default: Node's bundled roots (never the system store). */
  ca?: string[];
  timeoutMs?: number;
}

export class EgressHttpError extends Error {
  override name = "EgressHttpError";
}

class DialerAgent extends https.Agent {
  constructor(
    private readonly dialer: Dialer,
    private readonly ca: string[],
  ) {
    super({ keepAlive: false });
  }

  override createConnection(options: http.ClientRequestArgs & tls.ConnectionOptions, cb?: (err: Error | null, s: Duplex) => void): Duplex | undefined {
    const host = String(options.servername || options.host || options.hostname || "");
    const port = Number(options.port ?? 443);
    this.dialer.dial(host, port).then(
      (raw) => {
        const sock = tls.connect({
          socket: raw,
          servername: host,
          ca: this.ca,
          rejectUnauthorized: true,
          minVersion: "TLSv1.2",
        });
        cb?.(null, sock);
      },
      (err: Error) => cb?.(err, undefined as unknown as Duplex),
    );
    return undefined;
  }
}

export class EgressHttps {
  readonly agent: https.Agent;
  private readonly timeoutMs: number;

  constructor(opts: EgressHttpsOptions) {
    this.agent = new DialerAgent(opts.dialer, opts.ca ?? [...tls.rootCertificates]);
    this.timeoutMs = opts.timeoutMs ?? 15_000;
  }

  /** GET a URL and parse JSON. Only https; redirects are not followed. */
  async getJson(url: string, headers: Record<string, string> = {}): Promise<{ status: number; json: unknown }> {
    const u = new URL(url);
    if (u.protocol !== "https:") throw new EgressHttpError("only https URLs are allowed");
    return new Promise((resolve, reject) => {
      const req = https.request(
        u,
        { method: "GET", agent: this.agent, headers: { accept: "application/json", ...headers }, timeout: this.timeoutMs },
        (res) => {
          const chunks: Buffer[] = [];
          let size = 0;
          res.on("data", (d: Buffer) => {
            size += d.length;
            if (size > MAX_RESPONSE_BYTES) {
              req.destroy(new EgressHttpError("response too large"));
              return;
            }
            chunks.push(d);
          });
          res.on("end", () => {
            const text = Buffer.concat(chunks).toString("utf8");
            try {
              resolve({ status: res.statusCode ?? 0, json: text ? JSON.parse(text) : null });
            } catch {
              reject(new EgressHttpError(`non-JSON response from ${u.host} (HTTP ${res.statusCode})`));
            }
          });
          res.on("error", reject);
        },
      );
      req.on("timeout", () => req.destroy(new EgressHttpError(`timed out talking to ${u.host}`)));
      req.on("error", reject);
      req.end();
    });
  }
}
