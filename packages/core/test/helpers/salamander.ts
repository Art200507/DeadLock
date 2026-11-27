/**
 * Test-only: build one AES-256-GCM ciphertext that authenticates under two different keys
 * (the "invisible salamanders" / partitioning-oracle construction of Dodis et al. 2018 and
 * Len, Grubbs & Ristenpart 2021). GHASH is linear in the ciphertext blocks, so with one free
 * block X the two tag equations can be solved for X in GF(2^128).
 *
 * This is attack code for a test, never used by the product. Uses AES-ECB from node:crypto as
 * the block cipher and the GCM field arithmetic from NIST SP 800-38D.
 */
import { createCipheriv } from "node:crypto";

const R = 0xe1n << 120n;
const MASK = (1n << 128n) - 1n;

const toBig = (b: Uint8Array) => BigInt(`0x${Buffer.from(b).toString("hex") || "0"}`);
const toBytes = (x: bigint) => Buffer.from(x.toString(16).padStart(32, "0"), "hex");

function gfMul(x: bigint, y: bigint): bigint {
  let z = 0n;
  let v = y;
  for (let i = 127n; i >= 0n; i--) {
    if ((x >> i) & 1n) z ^= v;
    v = v & 1n ? (v >> 1n) ^ R : v >> 1n;
  }
  return z & MASK;
}

function gfPow(x: bigint, e: bigint): bigint {
  let r = 1n << 127n; // the field's 1 in GCM's bit-reflected representation
  let b = x;
  while (e > 0n) {
    if (e & 1n) r = gfMul(r, b);
    b = gfMul(b, b);
    e >>= 1n;
  }
  return r;
}

const gfInv = (x: bigint) => gfPow(x, (1n << 128n) - 2n);

function aesBlock(key: Uint8Array, block: Uint8Array): Uint8Array {
  const c = createCipheriv("aes-256-ecb", key, null);
  c.setAutoPadding(false);
  return new Uint8Array(Buffer.concat([c.update(block), c.final()]));
}

function blocks(data: Uint8Array): bigint[] {
  const out: bigint[] = [];
  for (let i = 0; i < data.length; i += 16) {
    const b = new Uint8Array(16);
    b.set(data.subarray(i, i + 16));
    out.push(toBig(b));
  }
  return out;
}

function ghash(h: bigint, all: bigint[]): bigint {
  let y = 0n;
  for (const b of all) y = gfMul(y ^ b, h);
  return y;
}

/**
 * A (nonce, ciphertext, tag) that opens under both k1 and k2 with this AAD. The ciphertext is
 * 2 blocks: the first is solved for, the second is arbitrary.
 */
export function craftTwoKeyCiphertext(k1: Uint8Array, k2: Uint8Array, aad: Uint8Array, nonce: Uint8Array) {
  const fixed = toBig(new Uint8Array(16).fill(0x42));
  const len = new Uint8Array(16);
  const dv = new DataView(len.buffer);
  dv.setBigUint64(0, BigInt(aad.length * 8));
  dv.setBigUint64(8, BigInt(32 * 8));
  const j0 = new Uint8Array(16);
  j0.set(nonce);
  j0[15] = 1;
  const params = [k1, k2].map((k) => ({ h: toBig(aesBlock(k, new Uint8Array(16))), s: toBig(aesBlock(k, j0)) }));
  const a = blocks(aad);
  const seq = (x: bigint) => [...a, x, fixed, toBig(len)];
  const e = BigInt(seq(0n).length - a.length); // exponent of H on the free block
  const [p1, p2] = params as [{ h: bigint; s: bigint }, { h: bigint; s: bigint }];
  const rhs = p1.s ^ p2.s ^ ghash(p1.h, seq(0n)) ^ ghash(p2.h, seq(0n));
  const x = gfMul(rhs, gfInv(gfPow(p1.h, e) ^ gfPow(p2.h, e)));
  const tag = p1.s ^ ghash(p1.h, seq(x));
  if (tag !== (p2.s ^ ghash(p2.h, seq(x)))) throw new Error("construction failed");
  return { ciphertext: new Uint8Array(Buffer.concat([toBytes(x), toBytes(fixed)])), tag: new Uint8Array(toBytes(tag)) };
}
