import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { describe, it } from "node:test";
import {
  HEADER_LENGTH,
  IntegrityError,
  NONCE_LENGTH,
  TAG_LENGTH,
  decryptBytes,
  encryptBytes,
  generateDek,
  generateId,
  importDek,
} from "../src/index.js";

const CHUNK = 1024; // small chunks keep these unit tests fast; vault tests use the 1 MiB default
const RECORD = NONCE_LENGTH + CHUNK + TAG_LENGTH;

async function ctx() {
  return { key: await importDek(generateDek()), vaultId: generateId(), fileId: generateId() };
}

/** Byte range of record i inside a ciphertext. */
const rec = (i: number) => [HEADER_LENGTH + i * RECORD, HEADER_LENGTH + (i + 1) * RECORD] as const;

describe("chunked AES-256-GCM stream", () => {
  it("round-trips empty, exact-chunk and odd-sized inputs", async () => {
    const c = await ctx();
    for (const n of [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 5 * CHUNK, 5 * CHUNK + 37]) {
      const plain = new Uint8Array(randomBytes(n));
      const cipher = await encryptBytes(plain, c, { chunkSize: CHUNK });
      const records = Math.max(1, Math.ceil(n / CHUNK));
      assert.equal(cipher.length, HEADER_LENGTH + n + records * (NONCE_LENGTH + TAG_LENGTH), `size for n=${n}`);
      assert.deepEqual(await decryptBytes(cipher, c), plain);
    }
  });

  it("uses a unique nonce for every chunk, and re-encryption differs", async () => {
    const c = await ctx();
    const plain = new Uint8Array(20 * CHUNK); // all zeros: identical plaintext chunks
    const a = await encryptBytes(plain, c, { chunkSize: CHUNK });
    const b = await encryptBytes(plain, c, { chunkSize: CHUNK });
    const nonces = new Set<string>();
    for (const ct of [a, b]) {
      for (let i = 0; i < 20; i++) {
        const [s] = rec(i);
        nonces.add(Buffer.from(ct.subarray(s, s + NONCE_LENGTH)).toString("hex"));
      }
    }
    assert.equal(nonces.size, 40);
    assert.notDeepEqual(a, b);
  });

  it("rejects a flipped byte anywhere: header, nonce, ciphertext, tag", async () => {
    const c = await ctx();
    const plain = new Uint8Array(randomBytes(3 * CHUNK + 10));
    const cipher = await encryptBytes(plain, c, { chunkSize: CHUNK });
    const positions = [
      4, // version byte
      HEADER_LENGTH - 1, // chunk size
      rec(0)[0], // first nonce byte
      rec(1)[0] + NONCE_LENGTH + 100, // ciphertext body
      rec(2)[1] - 1, // tag of a middle chunk
      cipher.length - 1, // tag of the final chunk
    ];
    for (const pos of positions) {
      const bad = cipher.slice();
      bad[pos]! ^= 0x01;
      await assert.rejects(decryptBytes(bad, c), IntegrityError, `flip at ${pos}`);
    }
  });

  it("rejects swapped and reordered chunks", async () => {
    const c = await ctx();
    const plain = new Uint8Array(randomBytes(4 * CHUNK)); // 4 full chunks, last one is final
    const cipher = await encryptBytes(plain, c, { chunkSize: CHUNK });
    const swap = (ct: Uint8Array, i: number, j: number) => {
      const out = ct.slice();
      out.set(ct.subarray(...rec(i)), rec(j)[0]);
      out.set(ct.subarray(...rec(j)), rec(i)[0]);
      return out;
    };
    await assert.rejects(decryptBytes(swap(cipher, 0, 1), c), IntegrityError);
    await assert.rejects(decryptBytes(swap(cipher, 1, 2), c), IntegrityError);
    await assert.rejects(decryptBytes(swap(cipher, 2, 3), c), IntegrityError, "swap with final chunk");
    // duplicate a chunk in place of another
    const dup = cipher.slice();
    dup.set(cipher.subarray(...rec(0)), rec(1)[0]);
    await assert.rejects(decryptBytes(dup, c), IntegrityError);
  });

  it("rejects truncation and appended chunks", async () => {
    const c = await ctx();
    const cipher = await encryptBytes(new Uint8Array(randomBytes(4 * CHUNK)), c, { chunkSize: CHUNK });
    await assert.rejects(decryptBytes(cipher.subarray(0, rec(3)[0]), c), IntegrityError, "drop final chunk");
    await assert.rejects(decryptBytes(cipher.subarray(0, cipher.length - 1), c), IntegrityError, "drop one byte");
    await assert.rejects(decryptBytes(cipher.subarray(0, HEADER_LENGTH), c), IntegrityError, "header only");
    await assert.rejects(decryptBytes(cipher.subarray(0, 10), c), IntegrityError, "partial header");
    const extended = new Uint8Array(cipher.length + RECORD);
    extended.set(cipher);
    extended.set(cipher.subarray(...rec(0)), cipher.length);
    await assert.rejects(decryptBytes(extended, c), IntegrityError, "appended chunk");
  });

  it("rejects chunks moved to another file or vault", async () => {
    const c = await ctx();
    const cipher = await encryptBytes(new Uint8Array(randomBytes(2 * CHUNK)), c, { chunkSize: CHUNK });
    await assert.rejects(decryptBytes(cipher, { ...c, fileId: generateId() }), IntegrityError, "other file ID");
    await assert.rejects(decryptBytes(cipher, { ...c, vaultId: generateId() }), IntegrityError, "other vault ID");

    // splice a chunk from another file under the same key and vault
    const other = await encryptBytes(new Uint8Array(randomBytes(2 * CHUNK)), { ...c, fileId: generateId() }, {
      chunkSize: CHUNK,
    });
    const spliced = cipher.slice();
    spliced.set(other.subarray(...rec(0)), rec(0)[0]);
    await assert.rejects(decryptBytes(spliced, c), IntegrityError, "chunk from another file");
  });

  it("rejects the wrong key", async () => {
    const c = await ctx();
    const cipher = await encryptBytes(new Uint8Array(randomBytes(CHUNK * 2)), c, { chunkSize: CHUNK });
    const wrong = await importDek(generateDek());
    await assert.rejects(decryptBytes(cipher, { ...c, key: wrong }), IntegrityError);
  });

  it("refuses keys that are not 256 bits", async () => {
    await assert.rejects(importDek(new Uint8Array(16)), TypeError);
    await assert.rejects(importDek(new Uint8Array(33)), TypeError);
  });
});
