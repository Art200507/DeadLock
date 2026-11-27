/**
 * Vault format v2: key commitment. A wrong key, a crafted multi-key ciphertext, or any edit to
 * vault.json is refused before anything is decrypted; v1 vaults still open.
 */
import assert from "node:assert/strict";
import { hkdfSync, randomBytes } from "node:crypto";
import * as fsp from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { after, before, describe, it } from "node:test";
import {
  HEADER_LENGTH,
  IntegrityError,
  VAULT_FORMAT_VERSION,
  WrongKeyError,
  createVault,
  decryptBytes,
  generateDek,
  importDek,
  openVault,
  readManifest,
  readVaultHeader,
  verifyVault,
} from "../src/index.js";
import { craftTwoKeyCiphertext } from "./helpers/salamander.js";

let work: string;
before(async () => (work = await fsp.mkdtemp(path.join(tmpdir(), "condlock-commit-"))));
after(() => fsp.rm(work, { recursive: true, force: true }));

let n = 0;
async function sample(opts: { formatVersion?: 1 | 2 } = {}) {
  const dir = path.join(work, `s${n++}`);
  await fsp.mkdir(path.join(dir, "in"), { recursive: true });
  await fsp.writeFile(path.join(dir, "in", "photo.jpg"), randomBytes(200_000));
  await fsp.writeFile(path.join(dir, "in", "note.txt"), "hello\n");
  const dek = generateDek();
  const vaultDir = path.join(dir, "vault");
  await createVault({ inputs: [path.join(dir, "in", "photo.jpg"), path.join(dir, "in", "note.txt")], vaultDir, dek, chunkSize: 64 * 1024, ...opts });
  return { dir, dek, vaultDir, out: path.join(dir, "out") };
}

const editHeader = async (vaultDir: string, f: (h: Record<string, unknown>) => void) => {
  const p = path.join(vaultDir, "vault.json");
  const h = JSON.parse(await fsp.readFile(p, "utf8"));
  f(h);
  await fsp.writeFile(p, JSON.stringify(h));
};

describe("key commitment (vault format v2)", () => {
  it("new vaults are v2, carry a commitment and round-trip", async () => {
    const s = await sample();
    const h = await readVaultHeader(s.vaultDir);
    assert.equal(VAULT_FORMAT_VERSION, 2);
    assert.equal(h.version, 2);
    assert.equal(h.kdf, "hkdf-sha256");
    assert.match(h.keyCommitment!, /^[0-9a-f]{64}$/);
    const { restored } = await openVault({ vaultDir: s.vaultDir, dek: s.dek, outDir: s.out });
    assert.equal(restored.length, 2);
  });

  it("a wrong key is refused by the commitment, before any ciphertext is read", async () => {
    const s = await sample();
    // Wreck the manifest: the right key would now hit an integrity error, a wrong key never gets that far.
    await fsp.writeFile(path.join(s.vaultDir, "manifest.enc"), randomBytes(100));
    await assert.rejects(readManifest(s.vaultDir, generateDek()), WrongKeyError);
    await assert.rejects(openVault({ vaultDir: s.vaultDir, dek: generateDek(), outDir: s.out }), WrongKeyError);
    await assert.rejects(verifyVault(s.vaultDir, generateDek()), WrongKeyError);
    const e = await readManifest(s.vaultDir, s.dek).catch((x) => x);
    assert.ok(e instanceof IntegrityError && !(e instanceof WrongKeyError));
    assert.equal(await fsp.stat(s.out).catch(() => null), null, "nothing was restored");
  });

  for (const [what, edit] of [
    ["chunk size", (h: Record<string, unknown>) => (h.chunkSize = 1024)],
    ["vault ID", (h: Record<string, unknown>) => (h.vaultId = randomBytes(16).toString("hex"))],
    ["key commitment", (h: Record<string, unknown>) => (h.keyCommitment = randomBytes(32).toString("hex"))],
    ["kdf removed", (h: Record<string, unknown>) => delete h.kdf],
    ["downgraded to v1 (skip the commitment)", (h: Record<string, unknown>) => (h.version = 1)],
    ["unknown version", (h: Record<string, unknown>) => (h.version = 3)],
  ] as const) {
    it(`an edited vault.json is refused even with the right key: ${what}`, async () => {
      const s = await sample();
      await editHeader(s.vaultDir, edit);
      await assert.rejects(openVault({ vaultDir: s.vaultDir, dek: s.dek, outDir: s.out }), IntegrityError);
      assert.equal(await fsp.stat(s.out).catch(() => null), null, "nothing was restored");
    });
  }

  it("old v1 vaults (no commitment) still open, and still reject a wrong key", async () => {
    const s = await sample({ formatVersion: 1 });
    const h = await readVaultHeader(s.vaultDir);
    assert.equal(h.version, 1);
    assert.equal(h.keyCommitment, undefined);
    await assert.rejects(openVault({ vaultDir: s.vaultDir, dek: generateDek(), outDir: s.out }), IntegrityError);
    const { restored } = await openVault({ vaultDir: s.vaultDir, dek: s.dek, outDir: s.out });
    assert.equal(restored.length, 2);
  });
});

describe("crafted ciphertext that authenticates under two keys", () => {
  const AAD_LABEL = Buffer.from("condlock/v1/chunk");
  const streamHeader = (fileId: Uint8Array, chunkSize: number) => {
    const h = Buffer.alloc(HEADER_LENGTH);
    Buffer.from("CLK1").copy(h, 0);
    h[4] = 1;
    Buffer.from(fileId).copy(h, 5);
    h.writeUInt32BE(chunkSize, 21);
    return h;
  };
  const finalAad = (header: Buffer, vaultId: Uint8Array) => {
    const tail = Buffer.alloc(9);
    tail.writeBigUInt64BE(0n, 0);
    tail[8] = 1;
    return new Uint8Array(Buffer.concat([AAD_LABEL, header, vaultId, tail]));
  };
  /** The same HKDF derivation as vault v2 (vault.ts), recomputed independently. */
  const v2Key = (dek: Uint8Array, vaultIdHex: string) =>
    new Uint8Array(hkdfSync("sha256", dek, Buffer.from(vaultIdHex, "hex"), "condlock/v2/aes-256-gcm-key", 32));

  it("plain AES-GCM accepts it under both keys, with different plaintexts (the attack is real)", async () => {
    const k1 = randomBytes(32);
    const k2 = randomBytes(32);
    const vaultId = randomBytes(16);
    const fileId = randomBytes(16);
    const header = streamHeader(fileId, 64);
    const nonce = randomBytes(12);
    const { ciphertext, tag } = craftTwoKeyCiphertext(k1, k2, finalAad(header, vaultId), nonce);
    const blob = new Uint8Array(Buffer.concat([header, nonce, ciphertext, tag]));
    const p1 = await decryptBytes(blob, { key: await importDek(k1), vaultId, fileId });
    const p2 = await decryptBytes(blob, { key: await importDek(k2), vaultId, fileId });
    assert.equal(p1.length, 32);
    assert.notDeepEqual(p1, p2, "one ciphertext, two different 'valid' plaintexts");
  });

  it("a v2 vault refuses the second key, even though its data authenticates under it", async () => {
    const s = await sample();
    const h = await readVaultHeader(s.vaultDir);
    const dek2 = generateDek();
    const manifest = await readManifest(s.vaultDir, s.dek);
    const entry = manifest.entries[0]!;
    const fileId = Buffer.from(entry.fileId, "hex");
    const vaultId = Buffer.from(h.vaultId, "hex");
    const header = streamHeader(fileId, h.chunkSize);
    const nonce = randomBytes(12);
    // Crafted for the keys vault v2 would actually use for each DEK.
    const { ciphertext, tag } = craftTwoKeyCiphertext(v2Key(s.dek, h.vaultId), v2Key(dek2, h.vaultId), finalAad(header, vaultId), nonce);
    const blob = new Uint8Array(Buffer.concat([header, nonce, ciphertext, tag]));
    await fsp.writeFile(path.join(s.vaultDir, "data", `${entry.fileId}.bin`), blob);
    // Sanity: the crafted stream really does authenticate under dek2's derived key.
    const asDek2 = await decryptBytes(blob, { key: await importDek(v2Key(dek2, h.vaultId)), vaultId, fileId });
    assert.equal(asDek2.length, 32);

    await assert.rejects(openVault({ vaultDir: s.vaultDir, dek: dek2, outDir: s.out }), WrongKeyError);
    // With the real key the stream authenticates too, but no longer matches the manifest's hash.
    await assert.rejects(verifyVault(s.vaultDir, s.dek), /does not match the manifest/);
  });
});
