/** The encrypted manifest: the only place file names and sizes are stored. */
import { webcrypto } from "node:crypto";
import { fromHex, toHex } from "./bytes.js";
import { ID_LENGTH } from "./keys.js";
import { IntegrityError, decryptBytes, encryptBytes } from "./stream.js";

/** The manifest is encrypted as its own stream under this reserved file ID. */
export const MANIFEST_FILE_ID = new Uint8Array(ID_LENGTH);

export interface ManifestEntry {
  /** Hex file ID; the ciphertext lives at data/<fileId>.bin. */
  fileId: string;
  /** Original base name of the file or folder. */
  name: string;
  /** "file" is stored as-is; "dir" is stored as a tar archive of the folder. */
  kind: "file" | "dir";
  /** Plaintext byte count of the stored stream (the tar size for folders). */
  size: number;
  /** SHA-256 of the stored plaintext stream, checked again after decryption. */
  sha256: string;
}

export interface Manifest {
  format: "condlock-manifest";
  version: 1;
  vaultId: string;
  createdAt: string;
  entries: ManifestEntry[];
}

export async function encryptManifest(
  manifest: Manifest,
  key: webcrypto.CryptoKey,
  vaultId: Uint8Array,
): Promise<Uint8Array> {
  if (manifest.vaultId !== toHex(vaultId)) throw new Error("manifest vaultId mismatch");
  const plain = new TextEncoder().encode(JSON.stringify(manifest));
  return encryptBytes(plain, { key, vaultId, fileId: MANIFEST_FILE_ID });
}

export async function decryptManifest(
  cipher: Uint8Array,
  key: webcrypto.CryptoKey,
  vaultId: Uint8Array,
): Promise<Manifest> {
  const plain = await decryptBytes(cipher, { key, vaultId, fileId: MANIFEST_FILE_ID });
  let m: unknown;
  try {
    m = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plain));
  } catch {
    throw new IntegrityError("manifest is not valid JSON");
  }
  return validateManifest(m, toHex(vaultId));
}

function validateManifest(m: unknown, vaultIdHex: string): Manifest {
  const bad = (why: string): never => {
    throw new IntegrityError(`invalid manifest: ${why}`);
  };
  if (typeof m !== "object" || m === null) bad("not an object");
  const o = m as Record<string, unknown>;
  if (o.format !== "condlock-manifest" || o.version !== 1) bad("unknown format");
  if (o.vaultId !== vaultIdHex) bad("vaultId mismatch");
  if (typeof o.createdAt !== "string") bad("createdAt");
  if (!Array.isArray(o.entries)) bad("entries");
  const seenIds = new Set<string>();
  const seenNames = new Set<string>();
  for (const e of o.entries as unknown[]) {
    const x = e as Record<string, unknown>;
    if (typeof x !== "object" || x === null) bad("entry");
    if (typeof x.fileId !== "string") bad("fileId");
    fromHex(x.fileId as string, ID_LENGTH);
    if (typeof x.name !== "string") bad("name");
    assertSafeName(x.name as string);
    if (x.kind !== "file" && x.kind !== "dir") bad("kind");
    if (typeof x.size !== "number" || !Number.isSafeInteger(x.size) || x.size < 0) bad("size");
    if (typeof x.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(x.sha256 as string)) bad("sha256");
    if (seenIds.has(x.fileId as string) || seenNames.has(x.name as string)) bad("duplicate entry");
    seenIds.add(x.fileId as string);
    seenNames.add(x.name as string);
  }
  return o as unknown as Manifest;
}

/** A single path component: no separators, no traversal, no control characters. */
export function assertSafeName(name: string): void {
  if (
    name.length === 0 ||
    name.length > 255 ||
    name === "." ||
    name === ".." ||
    /[/\\\0]/.test(name) ||
    // eslint-disable-next-line no-control-regex
    /[\x00-\x1f]/.test(name)
  ) {
    throw new IntegrityError(`unsafe file name: ${JSON.stringify(name)}`);
  }
}
