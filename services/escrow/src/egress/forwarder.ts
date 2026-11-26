/**
 * A byte forwarder: listen locally, connect each client to one fixed upstream, copy bytes both
 * ways. This is what the parent's `vsock-proxy` does in production (vsock port → host:443), and
 * what the enclave's socat does on the inside. Used by tests and local development to stand in
 * for both; it sees only TLS ciphertext.
 */
import * as net from "node:net";
import type { LocalTarget } from "./dialer.js";

export interface Forwarder {
  port: number;
  close(): Promise<void>;
}

export async function startForwarder(
  upstream: LocalTarget,
  opts: { onBytes?: (direction: "up" | "down", data: Buffer) => void } = {},
): Promise<Forwarder> {
  const sockets = new Set<net.Socket>();
  const server = net.createServer((client) => {
    const up = "path" in upstream ? net.createConnection(upstream.path) : net.createConnection(upstream.port, upstream.host);
    sockets.add(client);
    sockets.add(up);
    client.on("data", (d: Buffer) => opts.onBytes?.("up", d));
    up.on("data", (d: Buffer) => opts.onBytes?.("down", d));
    client.pipe(up);
    up.pipe(client);
    const kill = () => {
      client.destroy();
      up.destroy();
      sockets.delete(client);
      sockets.delete(up);
    };
    client.on("error", kill);
    up.on("error", kill);
    client.on("close", kill);
    up.on("close", kill);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    port: (server.address() as net.AddressInfo).port,
    close: () =>
      new Promise<void>((resolve) => {
        for (const s of sockets) s.destroy();
        server.close(() => resolve());
      }),
  };
}
