/**
 * On-disk vaults.
 *
 *   <vault>/vault.json        public header (format, version, vaultId, chunkSize) — no names or sizes
 *   <vault>/manifest.enc      encrypted manifest (names, kinds, sizes, hashes)
 *   <vault>/data/<id>.bin     one encrypted stream per entry; a folder is one tar stream
 *
 * Every byte is treated as opaque: photos, PDFs, videos, anything. Folders are packed to tar
 * before encryption. Decrypted output goes into a staging directory and only moves into place
 * after every stream has authenticated, so a tampered vault never leaves partial plaintext.
 */
import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import * as fsp from "node:fs/promises";
import * as path from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import tar from "tar-stream";
import { fromHex, toHex } from "./bytes.js";
import { ID_LENGTH, generateId, importDek } from "./keys.js";
import { type Manifest, type ManifestEntry, assertSafeName, decryptManifest, encryptManifest } from "./manifest.js";
import { DEFAULT_CHUNK_SIZE, FORMAT_VERSION, IntegrityError, decryptStream, encryptStream } from "./stream.js";

export interface VaultHeader {
  format: "condlock-vault";
  version: number;
  vaultId: string;
  chunkSize: number;
}

export interface CreateVaultOptions {
  /** Files and/or folders to lock. */
  inputs: string[];
  /** Directory to create; must not already exist. */
  vaultDir: string;
  /** The 32-byte data key. The caller generates, escrows and wipes it. */
  dek: Uint8Array;
  /** Override the vault ID (hex, 16 bytes). Random by default. */
  vaultId?: string;
  chunkSize?: number;
}

export interface OpenVaultOptions {
  vaultDir: string;
  dek: Uint8Array;
  /** Directory to restore into (created if missing). Existing names are never overwritten. */
  outDir: string;
}

const VAULT_JSON = "vault.json";
const MANIFEST_FILE = "manifest.enc";
const DATA_DIR = "data";

export async function createVault(opts: CreateVaultOptions): Promise<{ vaultId: string; manifest: Manifest }> {
  const vaultIdBytes = opts.vaultId ? fromHex(opts.vaultId, ID_LENGTH) : generateId();
  const vaultId = toHex(vaultIdBytes);
  const chunkSize = opts.chunkSize ?? DEFAULT_CHUNK_SIZE;
  const key = await importDek(opts.dek);

  if (opts.inputs.length === 0) throw new Error("nothing to lock");
  const sources = await Promise.all(
    opts.inputs.map(async (p) => {
      const st = await fsp.lstat(p);
      if (st.isSymbolicLink()) throw new Error(`symlinks are not supported: ${p}`);
      if (!st.isFile() && !st.isDirectory()) throw new Error(`not a regular file or folder: ${p}`);
      const name = path.basename(path.resolve(p));
      assertSafeName(name);
      return { path: p, name, kind: st.isDirectory() ? ("dir" as const) : ("file" as const) };
    }),
  );
  const names = new Set<string>();
  for (const s of sources) {
    if (names.has(s.name)) throw new Error(`two inputs share the name "${s.name}"`);
    names.add(s.name);
  }

  await fsp.mkdir(opts.vaultDir); // fails if it exists: never overwrite a vault
  try {
    await fsp.mkdir(path.join(opts.vaultDir, DATA_DIR));
    const entries: ManifestEntry[] = [];
    for (const s of sources) {
      const fileId = generateId();
      const hash = createHash("sha256");
      let size = 0;
      const plain = s.kind === "dir" ? packDirectory(s.path) : createReadStream(s.path, { highWaterMark: chunkSize });
      const counted = tap(plain, (c) => {
        hash.update(c);
        size += c.length;
      });
      await pipeline(
        Readable.from(encryptStream(counted, { key, vaultId: vaultIdBytes, fileId }, { chunkSize })),
        createWriteStream(path.join(opts.vaultDir, DATA_DIR, `${toHex(fileId)}.bin`), { flags: "wx" }),
      );
      entries.push({ fileId: toHex(fileId), name: s.name, kind: s.kind, size, sha256: hash.digest("hex") });
    }

    const manifest: Manifest = {
      format: "condlock-manifest",
      version: 1,
      vaultId,
      createdAt: new Date().toISOString(),
      entries,
    };
    await fsp.writeFile(path.join(opts.vaultDir, MANIFEST_FILE), await encryptManifest(manifest, key, vaultIdBytes), {
      flag: "wx",
    });
    const header: VaultHeader = { format: "condlock-vault", version: FORMAT_VERSION, vaultId, chunkSize };
    await fsp.writeFile(path.join(opts.vaultDir, VAULT_JSON), JSON.stringify(header, null, 2) + "\n", { flag: "wx" });
    return { vaultId, manifest };
  } catch (err) {
    await fsp.rm(opts.vaultDir, { recursive: true, force: true });
    throw err;
  }
}

export async function readVaultHeader(vaultDir: string): Promise<VaultHeader> {
  const raw = JSON.parse(await fsp.readFile(path.join(vaultDir, VAULT_JSON), "utf8")) as Partial<VaultHeader>;
  if (raw.format !== "condlock-vault" || raw.version !== FORMAT_VERSION || typeof raw.vaultId !== "string") {
    throw new IntegrityError("not a Condition Lock vault");
  }
  fromHex(raw.vaultId, ID_LENGTH);
  return raw as VaultHeader;
}

/** Decrypt only the manifest (names and sizes), e.g. for `condlock status`. */
export async function readManifest(vaultDir: string, dek: Uint8Array): Promise<Manifest> {
  const header = await readVaultHeader(vaultDir);
  const key = await importDek(dek);
  const cipher = new Uint8Array(await fsp.readFile(path.join(vaultDir, MANIFEST_FILE)));
  return decryptManifest(cipher, key, fromHex(header.vaultId, ID_LENGTH));
}

export async function openVault(opts: OpenVaultOptions): Promise<{ manifest: Manifest; restored: string[] }> {
  const header = await readVaultHeader(opts.vaultDir);
  const vaultIdBytes = fromHex(header.vaultId, ID_LENGTH);
  const key = await importDek(opts.dek);
  const manifest = await decryptManifest(
    new Uint8Array(await fsp.readFile(path.join(opts.vaultDir, MANIFEST_FILE))),
    key,
    vaultIdBytes,
  );

  await fsp.mkdir(opts.outDir, { recursive: true });
  for (const e of manifest.entries) {
    if (await exists(path.join(opts.outDir, e.name))) throw new Error(`refusing to overwrite ${e.name}`);
  }

  const staging = await fsp.mkdtemp(path.join(opts.outDir, ".condlock-staging-"));
  try {
    for (const e of manifest.entries) {
      const fileId = fromHex(e.fileId, ID_LENGTH);
      const hash = createHash("sha256");
      let size = 0;
      const plain = tap(
        decryptStream(createReadStream(path.join(opts.vaultDir, DATA_DIR, `${e.fileId}.bin`)), {
          key,
          vaultId: vaultIdBytes,
          fileId,
        }),
        (c) => {
          hash.update(c);
          size += c.length;
        },
      );
      const target = path.join(staging, e.name);
      if (e.kind === "file") {
        await pipeline(Readable.from(plain), createWriteStream(target, { flags: "wx" }));
      } else {
        await extractTar(plain, target);
      }
      if (size !== e.size || hash.digest("hex") !== e.sha256) {
        throw new IntegrityError(`${e.name}: decrypted content does not match the manifest`);
      }
    }
    const restored: string[] = [];
    for (const e of manifest.entries) {
      const dest = path.join(opts.outDir, e.name);
      await fsp.rename(path.join(staging, e.name), dest);
      restored.push(dest);
    }
    return { manifest, restored };
  } finally {
    await fsp.rm(staging, { recursive: true, force: true });
  }
}

// ---------- helpers ----------

async function exists(p: string): Promise<boolean> {
  try {
    await fsp.lstat(p);
    return true;
  } catch {
    return false;
  }
}

async function* tap(
  src: AsyncIterable<Uint8Array | Buffer>,
  onChunk: (c: Uint8Array) => void,
): AsyncGenerator<Uint8Array> {
  for await (const c of src) {
    const u = c instanceof Uint8Array ? c : new Uint8Array(c);
    onChunk(u);
    yield u;
  }
}

/** Pack a folder into a tar stream. Regular files and directories only; symlinks are rejected. */
function packDirectory(root: string): AsyncIterable<Uint8Array> {
  const pack = tar.pack();
  const walk = async (abs: string, rel: string): Promise<void> => {
    const dirents = (await fsp.readdir(abs, { withFileTypes: true })).sort((a, b) => (a.name < b.name ? -1 : 1));
    for (const d of dirents) {
      const childAbs = path.join(abs, d.name);
      const childRel = rel ? `${rel}/${d.name}` : d.name;
      const st = await fsp.lstat(childAbs);
      if (st.isDirectory()) {
        pack.entry({ name: `${childRel}/`, type: "directory", mode: st.mode & 0o777, mtime: st.mtime });
        await walk(childAbs, childRel);
      } else if (st.isFile()) {
        await new Promise<void>((resolve, reject) => {
          const entry = pack.entry(
            { name: childRel, type: "file", size: st.size, mode: st.mode & 0o777, mtime: st.mtime },
            (err) => (err ? reject(err) : resolve()),
          );
          pipeline(createReadStream(childAbs), entry).catch(reject);
        });
      } else {
        throw new Error(`unsupported file type (symlink or special file): ${childAbs}`);
      }
    }
  };
  walk(root, "").then(
    () => pack.finalize(),
    (err: Error) => pack.destroy(err),
  );
  return pack as unknown as AsyncIterable<Uint8Array>;
}

/** Extract a tar stream into `dest`, refusing anything that could escape it. */
async function extractTar(src: AsyncIterable<Uint8Array>, dest: string): Promise<void> {
  await fsp.mkdir(dest);
  const root = path.resolve(dest);
  const extract = tar.extract();
  const feed = pipeline(Readable.from(src), extract);
  const consume = (async () => {
    for await (const entry of extract) {
      const h = entry.header;
      const rel = h.name.replace(/\/+$/, "");
      const target = path.resolve(root, rel);
      if (
        path.isAbsolute(rel) ||
        rel.split("/").some((seg) => seg === ".." || seg === "") ||
        !target.startsWith(root + path.sep)
      ) {
        throw new IntegrityError(`unsafe path in archive: ${h.name}`);
      }
      if (h.type === "directory") {
        await fsp.mkdir(target, { recursive: true, mode: 0o700 });
        entry.resume();
      } else if (h.type === "file") {
        await fsp.mkdir(path.dirname(target), { recursive: true });
        await pipeline(entry, createWriteStream(target, { flags: "wx", mode: (h.mode ?? 0o600) & 0o777 }));
      } else {
        throw new IntegrityError(`unsupported archive entry type ${h.type}: ${h.name}`);
      }
    }
  })();
  await Promise.all([feed, consume]);
}

