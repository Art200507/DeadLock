/** Signed requests to the escrow API. Every /locks call is signed with this device's key. */
import type { KeyObject } from "node:crypto";
import { signRequest } from "@condlock/core";

export interface EscrowResponse {
  status: number;
  json: Record<string, any>;
}

export class EscrowUnreachableError extends Error {
  override name = "EscrowUnreachableError";
}

export interface EscrowClientOptions {
  url: string;
  deviceId: string;
  key: KeyObject;
  fetch: typeof fetch;
  /** The signing clock. The server rejects timestamps more than 5 minutes from its own. */
  now: () => Date;
}

export class EscrowClient {
  constructor(private readonly o: EscrowClientOptions) {}

  async call(method: "GET" | "POST", p: string, body?: unknown): Promise<EscrowResponse> {
    const raw = body === undefined ? "" : JSON.stringify(body);
    const headers = {
      ...signRequest({ deviceId: this.o.deviceId, privateKey: this.o.key, method, path: p, body: raw, timestamp: this.o.now().getTime() }),
      "content-type": "application/json",
    };
    let res: Response;
    try {
      res = await this.o.fetch(this.o.url + p, { method, headers, ...(method === "GET" ? {} : { body: raw }) });
    } catch (err) {
      throw new EscrowUnreachableError(`couldn't reach the escrow at ${this.o.url}: ${(err as Error).message}`);
    }
    const text = await res.text();
    let json: Record<string, any> = {};
    try {
      json = text ? (JSON.parse(text) as Record<string, any>) : {};
    } catch {
      json = { error: "bad-response", message: text.slice(0, 200) };
    }
    return { status: res.status, json };
  }
}

export async function registerDevice(o: {
  url: string;
  adminToken: string;
  publicKey: string;
  label: string;
  fetch: typeof fetch;
}): Promise<string> {
  let res: Response;
  try {
    res = await o.fetch(`${o.url}/devices`, {
      method: "POST",
      headers: { authorization: `Bearer ${o.adminToken}`, "content-type": "application/json" },
      body: JSON.stringify({ publicKey: o.publicKey, label: o.label }),
    });
  } catch (err) {
    throw new EscrowUnreachableError(`couldn't reach the escrow at ${o.url}: ${(err as Error).message}`);
  }
  const json = (await res.json().catch(() => ({}))) as { deviceId?: string; message?: string };
  if (res.status !== 201 || !json.deviceId) throw new Error(`device registration failed (${res.status}): ${json.message ?? "no details"}`);
  return json.deviceId;
}
