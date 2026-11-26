/**
 * Chunked AES-256-GCM streams (format v1).
 *
 *   header = "CLK1" | version u8 | fileId 16B | chunkSize u32be            (25 bytes)
 *   record = nonce 12B | AES-256-GCM ciphertext | tag 16B                  (one per chunk)
 *   AAD    = "condlock/v1/chunk" | header | vaultId 16B | index u64be | final u8
 *
 * Every chunk is sealed with a fresh random 96-bit nonce. The associated data binds each
 * chunk to its vault, file, position and chunk size, and marks the last chunk, so chunks
 * can't be swapped, reordered, moved between files or vaults, or dropped from the end.
 * All AES-GCM work is done by Node's WebCrypto; nothing here is custom cryptography.
 */
import { webcrypto } from "node:crypto";
import { ByteQueue, bytesEqual, concatBytes } from "./bytes.js";
import { ID_LENGTH } from "./keys.js";

const subtle = webcrypto.subtle;
type CryptoKey = webcrypto.CryptoKey;

export const MAGIC = new Uint8Array([0x43, 0x4c, 0x4b, 0x31]); // "CLK1"
export const FORMAT_VERSION = 1;
export const DEFAULT_CHUNK_SIZE = 1024 * 1024; // 1 MiB
export const MAX_CHUNK_SIZE = 16 * 1024 * 1024;
export const NONCE_LENGTH = 12;
export const TAG_LENGTH = 16;
export const HEADER_LENGTH = MAGIC.length + 1 + ID_LENGTH + 4;

const AAD_LABEL = new TextEncoder().encode("condlock/v1/chunk");

/** Raised whenever ciphertext fails to authenticate or is malformed. */
export class IntegrityError extends Error {
  override name = "IntegrityError";
}

export interface StreamContext {
  key: CryptoKey;
  vaultId: Uint8Array;
  fileId: Uint8Array;
}

export interface EncryptOptions {
  /** Plaintext bytes per chunk. Defaults to 1 MiB. */
  chunkSize?: number;
}

type ByteSource = AsyncIterable<Uint8Array> | Iterable<Uint8Array>;

function checkId(name: string, id: Uint8Array): void {
  if (!(id instanceof Uint8Array) || id.length !== ID_LENGTH) {
    throw new TypeError(`${name} must be ${ID_LENGTH} bytes`);
  }
}

function buildHeader(fileId: Uint8Array, chunkSize: number): Uint8Array {
  const h = new Uint8Array(HEADER_LENGTH);
  h.set(MAGIC, 0);
  h[MAGIC.length] = FORMAT_VERSION;
  h.set(fileId, MAGIC.length + 1);
  new DataView(h.buffer).setUint32(MAGIC.length + 1 + ID_LENGTH, chunkSize, false);
  return h;
}

function buildAad(header: Uint8Array, vaultId: Uint8Array, index: number, final: boolean) {
  const tail = new Uint8Array(9);
  const dv = new DataView(tail.buffer);
  dv.setBigUint64(0, BigInt(index), false);
  tail[8] = final ? 1 : 0;
  return concatBytes([AAD_LABEL, header, vaultId, tail]);
}

function toBytes(chunk: unknown): Uint8Array {
  if (chunk instanceof Uint8Array) return chunk;
  if (typeof chunk === "string") return new TextEncoder().encode(chunk);
  throw new TypeError("stream sources must yield Uint8Array chunks");
}

/** Encrypt a byte stream into a v1 ciphertext stream. Yields the header, then one record per chunk. */
export async function* encryptStream(
  source: ByteSource,
  ctx: StreamContext,
  opts: EncryptOptions = {},
): AsyncGenerator<Uint8Array> {
  checkId("vaultId", ctx.vaultId);
  checkId("fileId", ctx.fileId);
  const chunkSize = opts.chunkSize ?? DEFAULT_CHUNK_SIZE;
  if (!Number.isInteger(chunkSize) || chunkSize < 1 || chunkSize > MAX_CHUNK_SIZE) {
    throw new RangeError(`chunkSize must be between 1 and ${MAX_CHUNK_SIZE}`);
  }
  const header = buildHeader(ctx.fileId, chunkSize);

  const seal = async (plain: Uint8Array, index: number, final: boolean) => {
    const nonce = webcrypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
    const ct = await subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        additionalData: buildAad(header, ctx.vaultId, index, final),
        tagLength: TAG_LENGTH * 8,
      },
      ctx.key,
      plain,
    );
    return concatBytes([nonce, new Uint8Array(ct)]);
  };

  yield header;
  const queue = new ByteQueue();
  let index = 0;
  for await (const piece of source) {
    queue.push(toBytes(piece));
    // Strictly greater: keep at least one byte back so we know which chunk is final.
    while (queue.length > chunkSize) {
      yield await seal(queue.take(chunkSize), index++, false);
    }
  }
  // Always exactly one final record; an empty input is one empty final chunk.
  yield await seal(queue.take(queue.length), index, true);
}

/**
 * Decrypt a v1 ciphertext stream. Plaintext is yielded one authenticated chunk at a time;
 * the stream as a whole is only valid if the generator finishes without throwing, so
 * callers must not treat output as final until then.
 */
export async function* decryptStream(
  source: ByteSource,
  ctx: StreamContext,
): AsyncGenerator<Uint8Array> {
  checkId("vaultId", ctx.vaultId);
  checkId("fileId", ctx.fileId);
  const queue = new ByteQueue();
  let header: Uint8Array | undefined;
  let recordSize = 0;
  let index = 0;

  const open = async (record: Uint8Array, final: boolean) => {
    const nonce = record.subarray(0, NONCE_LENGTH);
    const body = record.subarray(NONCE_LENGTH);
    try {
      const pt = await subtle.decrypt(
        {
          name: "AES-GCM",
          iv: nonce,
          additionalData: buildAad(header!, ctx.vaultId, index, final),
          tagLength: TAG_LENGTH * 8,
        },
        ctx.key,
        body,
      );
      index++;
      return new Uint8Array(pt);
    } catch {
      throw new IntegrityError(
        `chunk ${index} failed authentication (wrong key, tampered, reordered or truncated data)`,
      );
    }
  };

  const readHeader = () => {
    const h = queue.take(HEADER_LENGTH);
    if (!bytesEqual(h.subarray(0, MAGIC.length), MAGIC)) {
      throw new IntegrityError("not a Condition Lock ciphertext (bad magic)");
    }
    if (h[MAGIC.length] !== FORMAT_VERSION) {
      throw new IntegrityError(`unsupported format version ${h[MAGIC.length]}`);
    }
    const fileId = h.subarray(MAGIC.length + 1, MAGIC.length + 1 + ID_LENGTH);
    if (!bytesEqual(fileId, ctx.fileId)) {
      throw new IntegrityError("ciphertext belongs to a different file");
    }
    const chunkSize = new DataView(h.buffer, h.byteOffset).getUint32(MAGIC.length + 1 + ID_LENGTH);
    if (chunkSize < 1 || chunkSize > MAX_CHUNK_SIZE) {
      throw new IntegrityError(`invalid chunk size ${chunkSize}`);
    }
    header = h;
    recordSize = NONCE_LENGTH + chunkSize + TAG_LENGTH;
  };

  for await (const piece of source) {
    queue.push(toBytes(piece));
    if (!header && queue.length >= HEADER_LENGTH) readHeader();
    // A record is non-final only if more bytes follow it.
    while (header && queue.length > recordSize) {
      yield await open(queue.take(recordSize), false);
    }
  }
  if (!header) throw new IntegrityError("ciphertext is truncated (no header)");
  if (queue.length < NONCE_LENGTH + TAG_LENGTH) {
    throw new IntegrityError("ciphertext is truncated (missing final chunk)");
  }
  yield await open(queue.take(queue.length), true);
}

/** Convenience: encrypt an in-memory buffer. */
export async function encryptBytes(
  plain: Uint8Array,
  ctx: StreamContext,
  opts: EncryptOptions = {},
): Promise<Uint8Array> {
  const out: Uint8Array[] = [];
  for await (const c of encryptStream([plain], ctx, opts)) out.push(c);
  return concatBytes(out);
}

/** Convenience: decrypt an in-memory buffer. */
export async function decryptBytes(cipher: Uint8Array, ctx: StreamContext): Promise<Uint8Array> {
  const out: Uint8Array[] = [];
  for await (const c of decryptStream([cipher], ctx)) out.push(c);
  return concatBytes(out);
}
