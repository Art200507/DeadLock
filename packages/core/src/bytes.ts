/** Small byte helpers. No cryptography lives here. */

export function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function toHex(b: Uint8Array): string {
  return Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString("hex");
}

export function fromHex(hex: string, expectedLength?: number): Uint8Array {
  if (!/^(?:[0-9a-f]{2})*$/.test(hex)) throw new Error("invalid hex string");
  const out = new Uint8Array(Buffer.from(hex, "hex"));
  if (expectedLength !== undefined && out.length !== expectedLength) {
    throw new Error(`expected ${expectedLength} bytes, got ${out.length}`);
  }
  return out;
}

/** FIFO byte buffer used to re-chunk an arbitrary stream into fixed-size pieces. */
export class ByteQueue {
  private parts: Uint8Array[] = [];
  private head = 0; // read offset into parts[0]
  length = 0;

  push(chunk: Uint8Array): void {
    if (chunk.length === 0) return;
    this.parts.push(chunk);
    this.length += chunk.length;
  }

  take(n: number): Uint8Array {
    if (n > this.length) throw new RangeError("ByteQueue underflow");
    const out = new Uint8Array(n);
    let filled = 0;
    while (filled < n) {
      const first = this.parts[0]!;
      const avail = first.length - this.head;
      const want = n - filled;
      if (avail <= want) {
        out.set(first.subarray(this.head), filled);
        filled += avail;
        this.parts.shift();
        this.head = 0;
      } else {
        out.set(first.subarray(this.head, this.head + want), filled);
        filled += want;
        this.head += want;
      }
    }
    this.length -= n;
    return out;
  }
}
