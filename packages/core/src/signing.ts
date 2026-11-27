/**
 * Ed25519 device-signed requests. Every API request carries:
 *
 *   x-condlock-device     registered device ID
 *   x-condlock-timestamp  Unix ms when signed (must be within the server's skew window)
 *   x-condlock-nonce      random, single-use (replay protection)
 *   x-condlock-signature  base64 Ed25519 signature over the canonical request below
 *
 *   canonical = "condlock-request-v1" \n METHOD \n path?query \n timestamp \n nonce \n sha256hex(body)
 *
 * Shared by the escrow server (verify) and the CLI (sign). Node's built-in Ed25519.
 */
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, verify, type KeyObject } from "node:crypto";

export const SIG_HEADERS = {
  device: "x-condlock-device",
  timestamp: "x-condlock-timestamp",
  nonce: "x-condlock-nonce",
  signature: "x-condlock-signature",
} as const;

export interface CanonicalRequest {
  method: string;
  /** Path plus query string, e.g. "/locks/abc/unlock". */
  path: string;
  timestamp: string;
  nonce: string;
  body: string | Uint8Array;
}

export function canonicalRequest(r: CanonicalRequest): string {
  const bodyHash = createHash("sha256").update(r.body).digest("hex");
  return ["condlock-request-v1", r.method.toUpperCase(), r.path, r.timestamp, r.nonce, bodyHash].join("\n");
}

export interface DeviceKeyPair {
  /** Raw 32-byte Ed25519 public key, base64url: what the server stores. */
  publicKey: string;
  privateKey: KeyObject;
}

export function generateDeviceKeyPair(): DeviceKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { publicKey: publicKey.export({ format: "jwk" }).x!, privateKey };
}

export function publicKeyFromRaw(rawBase64url: string): KeyObject {
  if (!/^[A-Za-z0-9_-]{43}$/.test(rawBase64url)) throw new TypeError("public key must be 32 bytes, base64url");
  return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: rawBase64url }, format: "jwk" });
}

export interface SignOptions {
  deviceId: string;
  privateKey: KeyObject;
  method: string;
  path: string;
  body?: string;
  /** Defaults to the signer's clock; the server decides whether it's acceptable. */
  timestamp?: number;
  nonce?: string;
}

/** Headers to attach to a request. */
export function signRequest(o: SignOptions): Record<string, string> {
  const timestamp = String(o.timestamp ?? Date.now());
  const nonce = o.nonce ?? randomBytes(16).toString("hex");
  const msg = canonicalRequest({ method: o.method, path: o.path, timestamp, nonce, body: o.body ?? "" });
  return {
    [SIG_HEADERS.device]: o.deviceId,
    [SIG_HEADERS.timestamp]: timestamp,
    [SIG_HEADERS.nonce]: nonce,
    [SIG_HEADERS.signature]: sign(null, Buffer.from(msg), o.privateKey).toString("base64"),
  };
}

export function verifySignature(publicKey: KeyObject, r: CanonicalRequest, signatureB64: string): boolean {
  try {
    return verify(null, Buffer.from(canonicalRequest(r)), publicKey, Buffer.from(signatureB64, "base64"));
  } catch {
    return false;
  }
}
