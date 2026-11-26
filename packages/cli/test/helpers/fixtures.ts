import { createHash, randomBytes } from "node:crypto";
import * as fsp from "node:fs/promises";
import * as path from "node:path";
import { QUICKNET, createDrandClient, generateDek, type DrandChain } from "@condlock/core";
import type { ChainClient } from "drand-client";
import type { CliContext } from "../../src/cli.js";

const MiB = 1024 * 1024;

/** A folder of mixed files: a photo, a PDF, a video-sized blob and a nested note. */
export async function makeMixedFolder(dir: string, videoBytes = 24 * MiB + 321): Promise<string> {
  await fsp.mkdir(path.join(dir, "nested", "deeper"), { recursive: true });
  const jpeg = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), randomBytes(3 * MiB + 17), Buffer.from([0xff, 0xd9])]);
  await fsp.writeFile(path.join(dir, "beach.jpg"), jpeg);
  await fsp.writeFile(
    path.join(dir, "ticket.pdf"),
    "%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n2 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n",
  );
  await fsp.writeFile(path.join(dir, "clip.mp4"), randomBytes(videoBytes));
  await fsp.writeFile(path.join(dir, "nested", "deeper", "notes — été.txt"), "level 42\n");
  return dir;
}

/** Relative path → sha256 for every file and folder under `root`. */
export async function hashTree(root: string): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  const walk = async (p: string) => {
    const st = await fsp.lstat(p);
    const rel = path.relative(root, p) || ".";
    if (st.isDirectory()) {
      out.set(rel + "/", "dir");
      for (const n of (await fsp.readdir(p)).sort()) await walk(path.join(p, n));
    } else {
      out.set(rel, createHash("sha256").update(await fsp.readFile(p)).digest("hex"));
    }
  };
  await walk(root);
  return out;
}

export async function allFiles(root: string): Promise<string[]> {
  const out: string[] = [];
  const walk = async (p: string) => {
    for (const e of await fsp.readdir(p, { withFileTypes: true })) {
      const full = path.join(p, e.name);
      if (e.isDirectory()) await walk(full);
      else out.push(full);
    }
  };
  await walk(root);
  return out;
}

export async function exists(p: string) {
  return fsp.lstat(p).then(
    () => true,
    () => false,
  );
}

export interface TestCtx extends CliContext {
  lines: string[];
  errLines: string[];
  prompts: string[];
  /** Copies of every data key handed out, and the live buffers (which should end up zeroed). */
  keysIssued: { copy: Uint8Array; live: Uint8Array }[];
  text(): string;
}

export function makeCtx(opts: {
  cwd: string;
  client?: ChainClient;
  chain?: DrandChain;
  answers?: string[];
}): TestCtx {
  const answers = [...(opts.answers ?? [])];
  const ctx: TestCtx = {
    cwd: opts.cwd,
    lines: [],
    errLines: [],
    prompts: [],
    keysIssued: [],
    out: (l) => ctx.lines.push(l),
    err: (l) => ctx.errLines.push(l),
    prompt: async (q) => {
      ctx.prompts.push(q);
      return answers.shift() ?? "";
    },
    client: opts.client ?? createDrandClient(QUICKNET),
    chain: opts.chain ?? QUICKNET,
    generateDek: () => {
      const live = generateDek();
      ctx.keysIssued.push({ copy: live.slice(), live });
      return live;
    },
    text: () => [...ctx.lines, ...ctx.errLines].join("\n"),
  };
  return ctx;
}
