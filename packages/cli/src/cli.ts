/**
 * condlock — lock files behind a time, locally, using drand timelock encryption.
 *
 *   condlock lock <path...> --until <time|duration> [--failsafe <time|duration>] [--vault <dir>] [--yes]
 *   condlock unlock <vault> [--out <dir>]
 *   condlock status <vault> [--offline]
 *   condlock log <vault>
 *
 * The data key lives only in memory: it is generated, used to encrypt and to make the two
 * tlock envelopes, then zeroed. Unlocking is decided by drand alone, never the laptop clock.
 */
import * as fsp from "node:fs/promises";
import { homedir } from "node:os";
import * as path from "node:path";
import { createInterface } from "node:readline/promises";
import { parseArgs, type ParseArgsConfig } from "node:util";
import {
  DrandUnavailableError,
  QUICKNET,
  StillLockedError,
  createDrandClient,
  createVault,
  generateDek,
  openVault,
  parseTlockEnvelope,
  readVaultHeader,
  roundForTime,
  serializeTlockEnvelope,
  timeOfRound,
  unwrapDek,
  verifyVault,
  wrapDek,
  zeroize,
  type DrandChain,
  type TlockEnvelope,
} from "@condlock/core";
import type { ChainClient } from "drand-client";
import { fetchBeacon } from "drand-client";
import { LOG_FILE, appendLog, readLog } from "./log.js";
import { DAY_MS, formatBytes, formatSpan, parseWhen } from "./time.js";

export const EXIT = { OK: 0, ERROR: 1, STILL_LOCKED: 2, DRAND_UNAVAILABLE: 3, CANCELLED: 4 } as const;

export const DEFAULT_FAILSAFE_MS = 365 * DAY_MS;
export const MIN_FAILSAFE_MS = 30 * DAY_MS;
export const CONFIRM_WORD = "delete";

const LOCK_FILE = "lock.json";
const KEYS_DIR = "keys";
const KEY_FILES = { timelock: "timelock.json", failsafe: "failsafe.json" } as const;

export interface CliContext {
  cwd: string;
  out: (line: string) => void;
  err: (line: string) => void;
  /** Ask the user for a line of input (used only for the delete confirmation). */
  prompt: (question: string) => Promise<string>;
  /** drand client and chain; defaults to the real quicknet. Tests pass a mock. */
  client: ChainClient;
  chain: DrandChain;
  /** Key generator; injectable so tests can check the key is zeroed and never hits disk. */
  generateDek: () => Uint8Array;
}

export interface LockFile {
  format: "condlock-lock";
  version: 1;
  vaultId: string;
  /** Laptop clock at lock time; informational only. */
  createdAt: string;
  condition: { type: "time"; round: number; unlockAt: string };
  failsafe: { round: number; unlockAt: string };
  keys: { timelock: string; failsafe: string };
}

export function defaultContext(): CliContext {
  return {
    cwd: process.cwd(),
    out: (l) => process.stdout.write(l + "\n"),
    err: (l) => process.stderr.write(l + "\n"),
    prompt: async (q) => {
      const rl = createInterface({ input: process.stdin, output: process.stderr });
      try {
        return await rl.question(q);
      } catch {
        return "";
      } finally {
        rl.close();
      }
    },
    client: createDrandClient(QUICKNET),
    chain: QUICKNET,
    generateDek,
  };
}

const USAGE = `usage:
  condlock lock <path...> --until <time|duration> [--failsafe <time|duration>] [--vault <dir>] [--yes]
  condlock unlock <vault> [--out <dir>]
  condlock status <vault> [--offline]
  condlock log <vault>

times:      2027-01-01T09:00Z, 2027-01-01 (midnight UTC), or a duration: 90s, 10m, 2h, 3d, 1w, 1y, 1h30m
fail-safe:  every vault also opens on its fail-safe date (default 1 year, minimum 30 days)`;

class UsageError extends Error {}

export async function run(argv: string[], ctx: CliContext = defaultContext()): Promise<number> {
  const [cmd, ...rest] = argv;
  try {
    switch (cmd) {
      case "lock":
        return await cmdLock(rest, ctx);
      case "unlock":
        return await cmdUnlock(rest, ctx);
      case "status":
        return await cmdStatus(rest, ctx);
      case "log":
        return await cmdLog(rest, ctx);
      case "help":
      case "--help":
      case "-h":
        ctx.out(USAGE);
        return EXIT.OK;
      default:
        throw new UsageError(cmd ? `unknown command "${cmd}"` : "no command given");
    }
  } catch (err) {
    if (err instanceof UsageError) {
      ctx.err(`condlock: ${err.message}\n\n${USAGE}`);
    } else {
      ctx.err(`condlock: ${(err as Error).message}`);
    }
    return EXIT.ERROR;
  }
}

function parse(args: string[], options: NonNullable<ParseArgsConfig["options"]>) {
  try {
    return parseArgs({ args, options, allowPositionals: true, strict: true });
  } catch (err) {
    throw new UsageError((err as Error).message);
  }
}

// ---------- lock ----------

async function cmdLock(args: string[], ctx: CliContext): Promise<number> {
  const { values, positionals } = parse(args, {
    until: { type: "string" },
    failsafe: { type: "string" },
    vault: { type: "string" },
    yes: { type: "boolean", short: "y" },
  });
  if (positionals.length === 0) throw new UsageError("lock needs at least one file or folder");
  if (typeof values.until !== "string") throw new UsageError("lock needs --until <time|duration>");

  const inputs = positionals.map((p) => path.resolve(ctx.cwd, p));
  for (const p of inputs) {
    await fsp.lstat(p).catch(() => {
      throw new Error(`no such file or folder: ${p}`);
    });
    assertSafeToDelete(p);
  }
  for (const a of inputs) {
    for (const b of inputs) {
      if (a !== b && isInside(b, a)) throw new Error(`${b} is inside ${a}; list it once`);
    }
  }
  const vaultDir = path.resolve(
    ctx.cwd,
    typeof values.vault === "string" ? values.vault : `${inputs[0]}.condlock`,
  );
  for (const p of inputs) {
    if (vaultDir === p || isInside(vaultDir, p)) throw new Error(`the vault can't be inside what it locks: ${p}`);
  }
  if (await exists(vaultDir)) throw new Error(`${vaultDir} already exists`);

  // "Now" for durations and sanity checks comes from drand's latest verified round.
  const now = await drandNow(ctx);
  if (!now.fromDrand) {
    ctx.err(`warning: couldn't reach drand, so durations are measured from this computer's clock (${now.date.toISOString()})`);
  }
  const until = parseWhen(values.until, now.date);
  if (until.getTime() <= now.date.getTime()) throw new Error(`--until ${until.toISOString()} is not in the future`);
  const failsafe =
    typeof values.failsafe === "string"
      ? parseWhen(values.failsafe, now.date)
      : new Date(Math.max(now.date.getTime() + DEFAULT_FAILSAFE_MS, until.getTime()));
  if (failsafe.getTime() < now.date.getTime() + MIN_FAILSAFE_MS) {
    throw new Error(`the fail-safe must be at least 30 days away (got ${failsafe.toISOString()})`);
  }
  if (failsafe.getTime() < until.getTime()) {
    throw new Error("the fail-safe can't be earlier than the unlock time");
  }
  const unlockRound = roundForTime(until, ctx.chain);
  const failsafeRound = roundForTime(failsafe, ctx.chain);
  const unlockAt = timeOfRound(unlockRound, ctx.chain);
  const failsafeAt = timeOfRound(failsafeRound, ctx.chain);

  // Show exactly what will happen, then ask.
  const items = await Promise.all(inputs.map(describeInput));
  ctx.out("condlock will encrypt and then DELETE these originals:");
  for (const it of items) ctx.out(`  ${it.path}  (${it.summary})`);
  ctx.out(`vault:      ${vaultDir}`);
  ctx.out(`unlocks:    ${unlockAt.toISOString()}  (drand round ${unlockRound}, in ${formatSpan(unlockAt.getTime() - now.date.getTime())})`);
  ctx.out(`fail-safe:  ${failsafeAt.toISOString()}  (drand round ${failsafeRound})`);
  ctx.out("Nothing, including you, can open the vault before then. Keep a copy first if you might need one.");
  if (!values.yes) {
    const answer = await ctx.prompt(`Type "${CONFIRM_WORD}" to lock and delete the originals: `);
    if (answer.trim() !== CONFIRM_WORD) {
      ctx.out("Cancelled. Nothing was changed.");
      return EXIT.CANCELLED;
    }
  }

  const dek = ctx.generateDek();
  let created = false;
  let vaultId: string;
  let entryCount: number;
  try {
    const result = await createVault({ inputs, vaultDir, dek });
    created = true;
    vaultId = result.vaultId;
    entryCount = result.manifest.entries.length;
    const timelock = await wrapDek({ dek, vaultId, target: { round: unlockRound }, chain: ctx.chain });
    const failsafeEnv = await wrapDek({ dek, vaultId, target: { round: failsafeRound }, chain: ctx.chain });
    await fsp.mkdir(path.join(vaultDir, KEYS_DIR));
    await fsp.writeFile(path.join(vaultDir, KEYS_DIR, KEY_FILES.timelock), serializeTlockEnvelope(timelock), { flag: "wx" });
    await fsp.writeFile(path.join(vaultDir, KEYS_DIR, KEY_FILES.failsafe), serializeTlockEnvelope(failsafeEnv), { flag: "wx" });
    const lock: LockFile = {
      format: "condlock-lock",
      version: 1,
      vaultId,
      createdAt: new Date().toISOString(),
      condition: { type: "time", round: unlockRound, unlockAt: unlockAt.toISOString() },
      failsafe: { round: failsafeRound, unlockAt: failsafeAt.toISOString() },
      keys: { timelock: `${KEYS_DIR}/${KEY_FILES.timelock}`, failsafe: `${KEYS_DIR}/${KEY_FILES.failsafe}` },
    };
    await fsp.writeFile(path.join(vaultDir, LOCK_FILE), JSON.stringify(lock, null, 2) + "\n", { flag: "wx" });
    // Prove the vault decrypts with this key before anything is deleted.
    await verifyVault(vaultDir, dek);
  } catch (err) {
    if (created) await fsp.rm(vaultDir, { recursive: true, force: true });
    throw new Error(`lock failed, originals untouched: ${(err as Error).message}`);
  } finally {
    zeroize(dek);
  }

  await appendLog(vaultDir, "locked", {
    vaultId,
    items: entryCount,
    unlockRound,
    unlockAt: unlockAt.toISOString(),
    failsafeRound,
    failsafeAt: failsafeAt.toISOString(),
    drandRoundAtLock: now.round,
  });

  for (const p of inputs) await fsp.rm(p, { recursive: true });
  await appendLog(vaultDir, "originals-deleted", { items: inputs.length });

  ctx.out(`Locked ${entryCount} item(s) into ${vaultDir}`);
  ctx.out(`Originals deleted (removed directly, not moved to the Trash).`);
  ctx.out(copiesChecklist());
  return EXIT.OK;
}

export function copiesChecklist(): string {
  return [
    "",
    "Copies may still live elsewhere. condlock can't see or delete these, so check them yourself:",
    "  [ ] Photos app and iCloud Photos (including Recently Deleted, kept for 30 days)",
    "  [ ] Google Photos / Google Drive (and their trash)",
    "  [ ] Time Machine and any other backups",
    "  [ ] Downloads, Desktop and email attachments",
    "  [ ] Chat apps: Messages, WhatsApp, Telegram, Slack, Discord",
    "  [ ] Cloud folders: iCloud Drive, Dropbox, OneDrive (they keep deleted files and versions)",
    "Note: on an SSD, deleted blocks can't be guaranteed gone; FileVault keeps them unreadable to others.",
    "Back up the vault folder anywhere you like; it's useless to anyone before its time.",
  ].join("\n");
}

// ---------- unlock ----------

async function cmdUnlock(args: string[], ctx: CliContext): Promise<number> {
  const { values, positionals } = parse(args, { out: { type: "string" } });
  const vaultDir = vaultArg(positionals, ctx);
  await vaultHeader(vaultDir);
  const envelopes = await readEnvelopes(vaultDir);
  const outDir = path.resolve(ctx.cwd, typeof values.out === "string" ? values.out : path.dirname(vaultDir));

  let dek: Uint8Array | undefined;
  let opened: { name: string; env: TlockEnvelope } | undefined;
  const locked: StillLockedError[] = [];
  for (const e of envelopes) {
    try {
      dek = await unwrapDek(e.env, { client: ctx.client });
      opened = e;
      break;
    } catch (err) {
      if (err instanceof StillLockedError) {
        locked.push(err);
        continue;
      }
      if (err instanceof DrandUnavailableError) {
        await appendLog(vaultDir, "unlock-attempt", { result: "drand-unavailable" });
        ctx.err(`Can't tell whether it's unlocked: ${err.message}. Nothing was changed; try again later.`);
        return EXIT.DRAND_UNAVAILABLE;
      }
      throw err;
    }
  }

  if (!dek || !opened) {
    const first = locked[0]!;
    await appendLog(vaultDir, "unlock-attempt", { result: "still-locked", round: first.round, latestRound: first.latestRound });
    ctx.out(`still locked until ${first.unlockAt.toISOString()}`);
    const rounds = first.round - first.latestRound;
    ctx.out(`  drand is at round ${first.latestRound}; ${rounds} more round(s), about ${formatSpan(rounds * ctx.chain.period * 1000)}`);
    const fs = locked.find((l) => l !== first);
    if (fs) ctx.out(`  fail-safe: ${fs.unlockAt.toISOString()}`);
    return EXIT.STILL_LOCKED;
  }

  try {
    const { restored } = await openVault({ vaultDir, dek, outDir });
    await appendLog(vaultDir, "unlocked", { via: opened.name, round: opened.env.round, items: restored.length });
    ctx.out(`Unlocked with the ${opened.name === "failsafe" ? "fail-safe" : "time-lock"} key (drand round ${opened.env.round}). Restored:`);
    for (const r of restored) ctx.out(`  ${r}`);
    ctx.out(`The vault is still at ${vaultDir}; delete it once you've checked your files.`);
    return EXIT.OK;
  } finally {
    zeroize(dek);
  }
}

// ---------- status ----------

async function cmdStatus(args: string[], ctx: CliContext): Promise<number> {
  const { values, positionals } = parse(args, { offline: { type: "boolean" } });
  const vaultDir = vaultArg(positionals, ctx);
  const header = await vaultHeader(vaultDir);
  const lock = JSON.parse(await fsp.readFile(path.join(vaultDir, LOCK_FILE), "utf8")) as LockFile;
  const envelopes = await readEnvelopes(vaultDir);
  const dataFiles = await fsp.readdir(path.join(vaultDir, "data"));
  let bytes = 0;
  for (const f of dataFiles) bytes += (await fsp.stat(path.join(vaultDir, "data", f))).size;
  const { entries } = await readLog(vaultDir);

  ctx.out(`vault:      ${vaultDir}`);
  ctx.out(`vault ID:   ${header.vaultId}`);
  ctx.out(`created:    ${lock.createdAt}`);
  ctx.out(`condition:  time-lock`);
  for (const e of envelopes) {
    const label = e.name === "failsafe" ? "fail-safe: " : "unlocks:   ";
    ctx.out(`${label} ${e.env.unlockAt}  (drand round ${e.env.round})`);
  }
  ctx.out(`contents:   ${dataFiles.length} encrypted item(s), ${formatBytes(bytes)} (names are encrypted)`);
  if (entries.some((e) => e.event === "unlocked")) {
    ctx.out("state:      opened before (see `condlock log`)");
  }

  if (values.offline) {
    ctx.out("state:      not checked (--offline)");
    return EXIT.OK;
  }
  let latest: number;
  try {
    latest = (await ctx.client.latest()).round;
  } catch {
    ctx.out("state:      unknown (couldn't reach drand)");
    return EXIT.OK;
  }
  const next = envelopes[0]!.env;
  if (latest >= next.round) {
    ctx.out(`state:      unlockable now (drand is at round ${latest}); run condlock unlock`);
  } else {
    const rounds = next.round - latest;
    ctx.out(`state:      locked; drand is at round ${latest}, ${rounds} round(s) to go (about ${formatSpan(rounds * ctx.chain.period * 1000)})`);
  }
  return EXIT.OK;
}

// ---------- log ----------

async function cmdLog(args: string[], ctx: CliContext): Promise<number> {
  const { positionals } = parse(args, {});
  const vaultDir = vaultArg(positionals, ctx);
  await vaultHeader(vaultDir);
  const { entries, broken } = await readLog(vaultDir);
  for (const e of entries) {
    const detail = Object.entries(e.detail)
      .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`)
      .join(" ");
    ctx.out(`${String(e.seq).padStart(3)}  ${e.at}  ${e.event.padEnd(18)} ${detail}`);
  }
  if (broken) {
    ctx.out(`WARNING: ${LOG_FILE} has been tampered with: ${broken}`);
    return EXIT.ERROR;
  }
  ctx.out(`(${entries.length} entries, chain intact)`);
  return EXIT.OK;
}

// ---------- helpers ----------

async function vaultHeader(vaultDir: string) {
  try {
    return await readVaultHeader(vaultDir);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") throw new Error(`${vaultDir} is not a Condition Lock vault (no vault.json)`);
    throw err;
  }
}

function vaultArg(positionals: string[], ctx: CliContext): string {
  if (positionals.length !== 1) throw new UsageError("expected exactly one vault directory");
  return path.resolve(ctx.cwd, positionals[0]!);
}

/** Envelopes sorted by round, earliest first. Each is validated by core before use. */
async function readEnvelopes(vaultDir: string): Promise<{ name: string; env: TlockEnvelope }[]> {
  const out: { name: string; env: TlockEnvelope }[] = [];
  for (const [name, file] of Object.entries(KEY_FILES)) {
    const p = path.join(vaultDir, KEYS_DIR, file);
    if (!(await exists(p))) continue;
    out.push({ name, env: parseTlockEnvelope(await fsp.readFile(p, "utf8")) });
  }
  if (out.length === 0) throw new Error(`no key envelopes in ${path.join(vaultDir, KEYS_DIR)}`);
  return out.sort((a, b) => a.env.round - b.env.round);
}

/** drand's latest verified round as "now"; falls back to the local clock only for choosing targets. */
async function drandNow(ctx: CliContext): Promise<{ date: Date; round: number | null; fromDrand: boolean }> {
  try {
    const latest = await ctx.client.latest();
    const verified = await fetchBeacon(ctx.client, latest.round);
    return { date: timeOfRound(verified.round, ctx.chain), round: verified.round, fromDrand: true };
  } catch {
    return { date: new Date(), round: null, fromDrand: false };
  }
}

async function describeInput(p: string): Promise<{ path: string; summary: string }> {
  const st = await fsp.lstat(p);
  if (st.isFile()) return { path: p, summary: `file, ${formatBytes(st.size)}` };
  let files = 0;
  let bytes = 0;
  const walk = async (d: string): Promise<void> => {
    for (const ent of await fsp.readdir(d, { withFileTypes: true })) {
      const full = path.join(d, ent.name);
      if (ent.isDirectory()) await walk(full);
      else {
        files++;
        bytes += (await fsp.lstat(full)).size;
      }
    }
  };
  await walk(p);
  return { path: p, summary: `folder, ${files} file(s), ${formatBytes(bytes)}` };
}

/** Refuse obviously catastrophic deletions: the filesystem root, the home folder or anything above it. */
export function assertSafeToDelete(p: string, home: string = homedir()): void {
  const abs = path.resolve(p);
  if (abs === path.parse(abs).root) throw new Error(`refusing to lock the filesystem root: ${abs}`);
  const h = path.resolve(home);
  if (abs === h || isInside(h, abs)) throw new Error(`refusing to lock your home folder or a folder containing it: ${abs}`);
}

function isInside(child: string, parent: string): boolean {
  const rel = path.relative(parent, child);
  return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}

async function exists(p: string): Promise<boolean> {
  try {
    await fsp.lstat(p);
    return true;
  } catch {
    return false;
  }
}
