import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import * as fsp from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { after, before, describe, it } from "node:test";
import {
  DEFAULT_CHUNK_SIZE,
  HEADER_LENGTH,
  IntegrityError,
  NONCE_LENGTH,
  TAG_LENGTH,
  createVault,
  generateDek,
  openVault,
  readManifest,
} from "../src/index.js";

const MiB = 1024 * 1024;
const RECORD = NONCE_LENGTH + DEFAULT_CHUNK_SIZE + TAG_LENGTH;
const rec = (i: number) => [HEADER_LENGTH + i * RECORD, HEADER_LENGTH + (i + 1) * RECORD] as const;

let work: string;
let inputs: string[];
let dek: Uint8Array;
let vaultDir: string;
let originalHashes: Map<string, string>;

const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");

/** Relative path -> sha256 for every file under dir (and the file itself if dir is a file). */
async function hashTree(p: string, base = p, out = new Map<string, string>()) {
  const st = await fsp.stat(p);
  if (st.isFile()) {
    out.set(path.relative(path.dirname(base), p), sha(await fsp.readFile(p)));
  } else {
    out.set(path.relative(path.dirname(base), p) + "/", "dir");
    for (const name of (await fsp.readdir(p)).sort()) await hashTree(path.join(p, name), base, out);
  }
  return out;
}

async function hashAll(paths: string[]) {
  const all = new Map<string, string>();
  for (const p of paths) for (const [k, v] of await hashTree(p)) all.set(k, v);
  return all;
}

/** Fresh copy of the vault so each tamper test starts clean. */
async function copyVault(tag: string) {
  const dir = path.join(work, `tamper-${tag}.condlock`);
  await fsp.cp(vaultDir, dir, { recursive: true });
  return dir;
}

async function dataFile(dir: string, name: string) {
  const m = await readManifest(dir, dek);
  const e = m.entries.find((x) => x.name === name)!;
  return path.join(dir, "data", `${e.fileId}.bin`);
}

async function assertNoPlaintextLeft(outDir: string) {
  const left = await fsp.readdir(outDir).catch(() => []);
  assert.deepEqual(left, [], `nothing should be restored, found: ${left.join(", ")}`);
}

before(async () => {
  work = await fsp.mkdtemp(path.join(tmpdir(), "condlock-test-"));
  const src = path.join(work, "src");
  await fsp.mkdir(src);

  // A "photo": JPEG markers around random data (content is opaque either way).
  const photo = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), randomBytes(3 * MiB + 4321), Buffer.from([0xff, 0xd9])]);
  await fsp.writeFile(path.join(src, "beach.jpg"), photo);

  // A small but valid PDF.
  const pdf = [
    "%PDF-1.4",
    "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
    "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
    "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >> endobj",
    "trailer << /Root 1 0 R >>",
    "%%EOF",
  ].join("\n");
  await fsp.writeFile(path.join(src, "contract.pdf"), pdf);

  // A video-sized blob: 64 MiB plus an odd tail, so the last chunk is partial.
  await fsp.writeFile(path.join(src, "clip.mp4"), randomBytes(64 * MiB + 777));

  // Edge cases: empty file and a file of exactly one chunk.
  await fsp.writeFile(path.join(src, "empty.bin"), "");
  await fsp.writeFile(path.join(src, "one-chunk.raw"), randomBytes(MiB));

  // A folder (packed to tar) with nesting, an empty dir and a non-ASCII name.
  const folder = path.join(src, "Game Saves");
  await fsp.mkdir(path.join(folder, "slot1", "deep"), { recursive: true });
  await fsp.mkdir(path.join(folder, "empty-dir"));
  await fsp.writeFile(path.join(folder, "slot1", "save.dat"), randomBytes(2 * MiB + 5));
  await fsp.writeFile(path.join(folder, "slot1", "deep", "notes — été.txt"), "level 42\n");
  await fsp.writeFile(path.join(folder, "config.json"), JSON.stringify({ difficulty: "hard" }));

  inputs = ["beach.jpg", "contract.pdf", "clip.mp4", "empty.bin", "one-chunk.raw", "Game Saves"].map((n) =>
    path.join(src, n),
  );
  originalHashes = await hashAll(inputs);
  dek = generateDek();
  vaultDir = path.join(work, "vault.condlock");
  await createVault({ inputs, vaultDir, dek });
});

after(async () => {
  await fsp.rm(work, { recursive: true, force: true });
});

describe("vault on disk", () => {
  it("round-trips mixed files and a folder byte-for-byte", async () => {
    const out = path.join(work, "restored");
    const { restored } = await openVault({ vaultDir, dek, outDir: out });
    assert.equal(restored.length, inputs.length);
    assert.deepEqual(await hashAll(restored), originalHashes);
    // No staging directory left behind.
    assert.deepEqual((await fsp.readdir(out)).sort(), inputs.map((p) => path.basename(p)).sort());
  });

  it("stores no names or sizes in the clear", async () => {
    const header = await fsp.readFile(path.join(vaultDir, "vault.json"), "utf8");
    const dataNames = await fsp.readdir(path.join(vaultDir, "data"));
    const manifestRaw = await fsp.readFile(path.join(vaultDir, "manifest.enc"));
    for (const p of inputs) {
      const n = path.basename(p);
      assert.ok(!header.includes(n));
      assert.ok(!dataNames.some((d) => d.includes(n)));
      assert.ok(!manifestRaw.includes(Buffer.from(n)), `${n} visible in manifest.enc`);
    }
    assert.ok(dataNames.every((d) => /^[0-9a-f]{32}\.bin$/.test(d)));
    const m = await readManifest(vaultDir, dek);
    assert.equal(m.entries.find((e) => e.name === "clip.mp4")!.size, 64 * MiB + 777);
    assert.equal(m.entries.find((e) => e.name === "Game Saves")!.kind, "dir");
  });

  it("fails on a flipped byte in a file, and restores nothing", async () => {
    const dir = await copyVault("flip");
    const f = await dataFile(dir, "clip.mp4");
    const buf = await fsp.readFile(f);
    buf[rec(40)[0] + NONCE_LENGTH + 12345]! ^= 0x80; // deep inside the video
    await fsp.writeFile(f, buf);
    const out = path.join(work, "out-flip");
    await assert.rejects(openVault({ vaultDir: dir, dek, outDir: out }), IntegrityError);
    await assertNoPlaintextLeft(out);
  });

  it("fails on a flipped byte in the manifest", async () => {
    const dir = await copyVault("flip-manifest");
    const f = path.join(dir, "manifest.enc");
    const buf = await fsp.readFile(f);
    buf[buf.length - 20]! ^= 0x01;
    await fsp.writeFile(f, buf);
    await assert.rejects(readManifest(dir, dek), IntegrityError);
    await assert.rejects(openVault({ vaultDir: dir, dek, outDir: path.join(work, "out-flip-m") }), IntegrityError);
  });

  it("fails on swapped chunks inside a file, and restores nothing", async () => {
    const dir = await copyVault("swap");
    const f = await dataFile(dir, "clip.mp4");
    const buf = await fsp.readFile(f);
    const a = Buffer.from(buf.subarray(...rec(3)));
    buf.copy(buf, rec(3)[0], ...rec(4));
    a.copy(buf, rec(4)[0]);
    await fsp.writeFile(f, buf);
    const out = path.join(work, "out-swap");
    await assert.rejects(openVault({ vaultDir: dir, dek, outDir: out }), IntegrityError);
    await assertNoPlaintextLeft(out);
  });

  it("fails when two encrypted files are swapped on disk", async () => {
    const dir = await copyVault("swap-files");
    const a = await dataFile(dir, "beach.jpg");
    const b = await dataFile(dir, "one-chunk.raw");
    const tmp = a + ".tmp";
    await fsp.rename(a, tmp);
    await fsp.rename(b, a);
    await fsp.rename(tmp, b);
    const out = path.join(work, "out-swap-files");
    await assert.rejects(openVault({ vaultDir: dir, dek, outDir: out }), IntegrityError);
    await assertNoPlaintextLeft(out);
  });

  it("fails when the last chunk of a file is cut off", async () => {
    const dir = await copyVault("truncate");
    const f = await dataFile(dir, "clip.mp4");
    const buf = await fsp.readFile(f);
    await fsp.writeFile(f, buf.subarray(0, rec(64)[0])); // keep 64 full chunks, drop the final partial one
    const out = path.join(work, "out-truncate");
    await assert.rejects(openVault({ vaultDir: dir, dek, outDir: out }), IntegrityError);
    await assertNoPlaintextLeft(out);
  });

  it("fails with the wrong key", async () => {
    const out = path.join(work, "out-wrong-key");
    await assert.rejects(openVault({ vaultDir, dek: generateDek(), outDir: out }), IntegrityError);
    await assert.rejects(readManifest(vaultDir, generateDek()), IntegrityError);
    await assertNoPlaintextLeft(out);
  });

  it("fails when vault.json claims a different vault ID", async () => {
    const dir = await copyVault("vault-id");
    const f = path.join(dir, "vault.json");
    const h = JSON.parse(await fsp.readFile(f, "utf8"));
    h.vaultId = "00112233445566778899aabbccddeeff";
    await fsp.writeFile(f, JSON.stringify(h));
    await assert.rejects(readManifest(dir, dek), IntegrityError);
  });

  it("never overwrites existing files when restoring", async () => {
    const out = path.join(work, "out-existing");
    await fsp.mkdir(out);
    await fsp.writeFile(path.join(out, "contract.pdf"), "mine");
    await assert.rejects(openVault({ vaultDir, dek, outDir: out }), /refusing to overwrite/);
    assert.equal(await fsp.readFile(path.join(out, "contract.pdf"), "utf8"), "mine");
  });

  it("refuses to create a vault over an existing directory", async () => {
    await assert.rejects(createVault({ inputs, vaultDir, dek }), /EEXIST/);
  });
});
