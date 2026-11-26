/**
 * The vault's local append-only log (log.jsonl). Each line carries the SHA-256 of the line
 * before it, so editing or deleting a line in the middle is detectable. A local file can still
 * be truncated or deleted outright; the escrow's server-side audit log (milestone 4) is the
 * one that can't be. Names are never logged: they live only in the encrypted manifest.
 */
import { createHash } from "node:crypto";
import * as fsp from "node:fs/promises";
import * as path from "node:path";

export const LOG_FILE = "log.jsonl";
const GENESIS = "0".repeat(64);

export interface LogEntry {
  seq: number;
  /** Laptop clock, for reading only; never used to decide anything. */
  at: string;
  event: string;
  detail: Record<string, unknown>;
  /** sha256 of the previous raw line (all zeros for the first). */
  prev: string;
}

const sha = (s: string) => createHash("sha256").update(s).digest("hex");

export interface ReadLogResult {
  entries: LogEntry[];
  /** null if the chain verifies; otherwise a description of the first break. */
  broken: string | null;
}

export async function readLog(vaultDir: string): Promise<ReadLogResult> {
  let raw: string;
  try {
    raw = await fsp.readFile(path.join(vaultDir, LOG_FILE), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return { entries: [], broken: "log file is missing" };
    throw err;
  }
  const lines = raw.split("\n").filter((l) => l.length > 0);
  const entries: LogEntry[] = [];
  let prev = GENESIS;
  for (let i = 0; i < lines.length; i++) {
    let e: LogEntry;
    try {
      e = JSON.parse(lines[i]!) as LogEntry;
    } catch {
      return { entries, broken: `line ${i + 1} is not valid JSON` };
    }
    if (e.prev !== prev || e.seq !== i + 1) {
      return { entries, broken: `line ${i + 1} doesn't follow line ${i} (edited, removed or reordered)` };
    }
    entries.push(e);
    prev = sha(lines[i]!);
  }
  return { entries, broken: null };
}

export async function appendLog(vaultDir: string, event: string, detail: Record<string, unknown> = {}): Promise<void> {
  const file = path.join(vaultDir, LOG_FILE);
  let lines: string[] = [];
  try {
    lines = (await fsp.readFile(file, "utf8")).split("\n").filter((l) => l.length > 0);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  // Chain onto whatever is there. If earlier lines were tampered with, the break stays visible
  // at its own position and new events are still recorded after it.
  const entry: LogEntry = {
    seq: lines.length + 1,
    at: new Date().toISOString(),
    event,
    detail,
    prev: lines.length ? sha(lines[lines.length - 1]!) : GENESIS,
  };
  await fsp.appendFile(file, JSON.stringify(entry) + "\n", { flag: "a" });
}
