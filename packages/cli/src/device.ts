/**
 * This computer's escrow identity: an Ed25519 key pair registered with the escrow, stored in
 * $CONDLOCK_HOME/device.json (default ~/.condlock), readable only by you. It authenticates
 * requests; it is not a vault key and can't decrypt anything.
 */
import { createPrivateKey, type KeyObject } from "node:crypto";
import * as fsp from "node:fs/promises";
import * as path from "node:path";

export interface DeviceConfig {
  format: "condlock-device";
  version: 1;
  escrowUrl: string;
  deviceId: string;
  publicKey: string;
  /** PKCS#8 DER, base64. */
  privateKey: string;
  label: string;
}

export const DEVICE_FILE = "device.json";

export async function loadDevice(home: string): Promise<(DeviceConfig & { key: KeyObject }) | null> {
  let raw: string;
  try {
    raw = await fsp.readFile(path.join(home, DEVICE_FILE), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
  const d = JSON.parse(raw) as DeviceConfig;
  if (d.format !== "condlock-device" || d.version !== 1) throw new Error(`${path.join(home, DEVICE_FILE)} is not a condlock device file`);
  return { ...d, key: createPrivateKey({ key: Buffer.from(d.privateKey, "base64"), format: "der", type: "pkcs8" }) };
}

export async function saveDevice(home: string, d: DeviceConfig): Promise<string> {
  await fsp.mkdir(home, { recursive: true, mode: 0o700 });
  const file = path.join(home, DEVICE_FILE);
  await fsp.writeFile(file, JSON.stringify(d, null, 2) + "\n", { flag: "wx", mode: 0o600 });
  return file;
}

/** https only, except for this machine (local development and the end-to-end tests). */
export function checkEscrowUrl(url: string): string {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new Error(`not a URL: ${url}`);
  }
  const local = ["127.0.0.1", "localhost", "[::1]"].includes(u.hostname);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) throw new Error("the escrow URL must use https");
  return u.origin;
}
