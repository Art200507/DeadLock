import { webcrypto } from "node:crypto";

const subtle = webcrypto.subtle;

export const DEK_LENGTH = 32; // 256-bit AES key
export const ID_LENGTH = 16; // 128-bit random IDs for vaults and files

/** A fresh random 256-bit data key. The caller owns it and should `zeroize` it when done. */
export function generateDek(): Uint8Array {
  return webcrypto.getRandomValues(new Uint8Array(DEK_LENGTH));
}

/** A fresh random 128-bit identifier (never all-zero; that value is reserved for the manifest). */
export function generateId(): Uint8Array {
  for (;;) {
    const id = webcrypto.getRandomValues(new Uint8Array(ID_LENGTH));
    if (id.some((b) => b !== 0)) return id;
  }
}

/** Import a raw DEK as a non-extractable AES-256-GCM WebCrypto key. */
export async function importDek(raw: Uint8Array): Promise<webcrypto.CryptoKey> {
  if (!(raw instanceof Uint8Array) || raw.length !== DEK_LENGTH) {
    throw new TypeError(`data key must be ${DEK_LENGTH} bytes`);
  }
  return subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/** Best-effort wipe of key material held in a JS buffer. */
export function zeroize(buf: Uint8Array): void {
  buf.fill(0);
}
