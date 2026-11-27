/**
 * condlock — lock files behind a time or an NFL result.
 *
 *   condlock device register --escrow <url> [--label <name>]      (admin token in CONDLOCK_ADMIN_TOKEN)
 *   condlock lock <path...> --until <time|duration> [--escrow] [--failsafe ...] [--vault <dir>] [--yes]
 *   condlock lock <path...> --nfl <condition.json> [--guardian <age1...>] [--failsafe ...] [--yes]
 *   condlock unlock <vault> [--out <dir>] [--guardian-share <file>]
 *   condlock status <vault> [--offline]
 *   condlock log <vault> [--server]
 *
 * The data key lives only in memory: it is generated, used to encrypt, to make the tlock
 * envelopes and (with an escrow) sent once over TLS to be sealed, then zeroed. Unlocking is
 * decided by drand rounds and the escrow's verifier, never by this computer's clock.
 */
import { readFileSync } from "node:fs";
import * as fsp from "node:fs/promises";
import { homedir } from "node:os";
import * as path from "node:path";
import { createInterface } from "node:readline/promises";
import { parseArgs, type ParseArgsConfig } from "node:util";
import { generateKeyPairSync } from "node:crypto";
import {
  DrandUnavailableError,
  QUICKNET,
  QUICKNET_RELAYS,
  StillLockedError,
  chainFromInfo,
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
  type VaultHeader,
} from "@condlock/core";
import { checkEscrowUrl, loadDevice, saveDevice } from "./device.js";
import { EscrowClient, EscrowUnreachableError, registerDevice } from "./escrow-client.js";
import type { ChainClient } from "drand-client";
import { fetchBeacon } from "drand-client";
import { LOG_FILE, appendLog, readLog } from "./log.js";
import { DAY_MS, formatBytes, formatSpan, parseWhen } from "./time.js";

export const EXIT = { OK: 0, ERROR: 1, STILL_LOCKED: 2, DRAND_UNAVAILABLE: 3, CANCELLED: 4, ESCROW_UNAVAILABLE: 5 } as const;

export const DEFAULT_FAILSAFE_MS = 365 * DAY_MS;
export const MIN_FAILSAFE_MS = 30 * DAY_MS;
export const CONFIRM_WORD = "delete";

const LOCK_FILE = "lock.json";
const KEYS_DIR = "keys";
const KEY_FILES = { timelock: "timelock.json", failsafe: "failsafe.json" } as const;
const GUARDIAN_SHARE_FILE = "guardian-share.age";

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
  /** Where this computer's escrow device key lives ($CONDLOCK_HOME, default ~/.condlock). */
  home: string;
  fetch: typeof fetch;
  /** This computer's clock: only for signing request timestamps. Never decides a lock. */
  now: () => Date;
  env: Record<string, string | undefined>;
}

export interface LockFile {
  format: "condlock-lock";
  /** 1: local tlock only (milestone 3). 2: adds the vault header copy and the escrow record. */
  version: 1 | 2;
  vaultId: string;
  /** Laptop clock at lock time; informational only. */
  createdAt: string;
  condition: { type: "time"; round: number; unlockAt: string } | { type: "nfl"; rule: Record<string, unknown> };
  failsafe: { round: number; unlockAt: string };
  keys: { timelock?: string; failsafe: string; guardianShare?: string };
  /** A copy of vault.json, compared before asking the escrow so a damaged header can't waste the one release. */
  vaultHeader?: VaultHeader;
  escrow?: { url: string; deviceId: string; keyScheme: string; conditionSha256: string };
}

export function defaultContext(env: Record<string, string | undefined> = process.env): CliContext {
  // Test/staging hooks for a private drand network. They can't help anyone cheat: tlock keys
  // only open with signatures from the chain they were made for, and the escrow pins its own.
  let chain = QUICKNET;
  let client: ChainClient;
  if (env.CONDLOCK_DRAND_CHAIN_FILE) {
    chain = chainFromInfo(JSON.parse(readFileSyncUtf8(env.CONDLOCK_DRAND_CHAIN_FILE)));
    process.stderr.write(`condlock: using drand chain ${chain.hash.slice(0, 12)}… from CONDLOCK_DRAND_CHAIN_FILE (not quicknet)\n`);
  }
  client = createDrandClient(chain, env.CONDLOCK_DRAND_URL ?? QUICKNET_RELAYS[0]);
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
    client,
    chain,
    generateDek,
    home: env.CONDLOCK_HOME ?? path.join(homedir(), ".condlock"),
    fetch: globalThis.fetch.bind(globalThis),
    now: () => new Date(),
    env,
  };
}

function readFileSyncUtf8(p: string): string {
  return readFileSync(p, "utf8");
}

const USAGE = `usage:
  condlock device register --escrow <url> [--label <name>]   (admin token in CONDLOCK_ADMIN_TOKEN)
  condlock lock <path...> --until <time|duration> [--escrow] [--failsafe <time|duration>] [--vault <dir>] [--yes]
  condlock lock <path...> --nfl <condition.json> [--guardian <age1...>] [--failsafe <time|duration>] [--yes]
  condlock unlock <vault> [--out <dir>] [--guardian-share <file>]
  condlock status <vault> [--offline]
  condlock log <vault> [--server]

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
      case "device":
        return await cmdDevice(rest, ctx);
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

interface NflRule {
  type: "nfl";
  game: { home: string; away: string; kickoffAt: string; apiSportsId: string; theSportsDbId: string };
  team: string;
  outcome: string;
  ifTie: string;
  ifPostponed: string;
  ifCancelled: string;
}

async function readNflRule(file: string): Promise<NflRule> {
  let rule: NflRule;
  try {
    rule = JSON.parse(await fsp.readFile(file, "utf8")) as NflRule;
  } catch (err) {
    throw new Error(`couldn't read the NFL condition ${file}: ${(err as Error).message}`);
  }
  if (rule?.type !== "nfl" || typeof rule.game !== "object" || typeof rule.team !== "string") {
    throw new Error(`${file} is not an NFL condition (see services/escrow/README.md for the format)`);
  }
  return rule;
}

async function escrowFor(ctx: CliContext): Promise<{ client: EscrowClient; url: string; deviceId: string }> {
  const device = await loadDevice(ctx.home);
  if (!device) throw new Error(`this computer has no escrow device yet; run: condlock device register --escrow <url>`);
  const client = new EscrowClient({ url: device.escrowUrl, deviceId: device.deviceId, key: device.key, fetch: ctx.fetch, now: ctx.now });
  return { client, url: device.escrowUrl, deviceId: device.deviceId };
}

async function cmdLock(args: string[], ctx: CliContext): Promise<number> {
  const { values, positionals } = parse(args, {
    until: { type: "string" },
    nfl: { type: "string" },
    escrow: { type: "boolean" },
    guardian: { type: "string" },
    failsafe: { type: "string" },
    vault: { type: "string" },
    yes: { type: "boolean", short: "y" },
  });
  if (positionals.length === 0) throw new UsageError("lock needs at least one file or folder");
  const hasUntil = typeof values.until === "string";
  const hasNfl = typeof values.nfl === "string";
  if (hasUntil === hasNfl) throw new UsageError("lock needs exactly one of --until <time|duration> or --nfl <condition.json>");
  const useEscrow = hasNfl || values.escrow === true || typeof values.guardian === "string";
  const nflRule = hasNfl ? await readNflRule(path.resolve(ctx.cwd, values.nfl as string)) : undefined;

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
  const escrow = useEscrow ? await escrowFor(ctx) : undefined;

  // "Now" for durations and sanity checks comes from drand's latest verified round.
  const now = await drandNow(ctx);
  if (!now.fromDrand) {
    ctx.err(`warning: couldn't reach drand, so durations are measured from this computer's clock (${now.date.toISOString()})`);
  }
  const until = hasUntil ? parseWhen(values.until as string, now.date) : undefined;
  if (until && until.getTime() <= now.date.getTime()) throw new Error(`--until ${until.toISOString()} is not in the future`);
  const failsafe =
    typeof values.failsafe === "string"
      ? parseWhen(values.failsafe, now.date)
      : new Date(Math.max(now.date.getTime() + DEFAULT_FAILSAFE_MS, until?.getTime() ?? 0));
  if (failsafe.getTime() < now.date.getTime() + MIN_FAILSAFE_MS) {
    throw new Error(`the fail-safe must be at least 30 days away (got ${failsafe.toISOString()})`);
  }
  if (until && failsafe.getTime() < until.getTime()) {
    throw new Error("the fail-safe can't be earlier than the unlock time");
  }
  const unlockRound = until ? roundForTime(until, ctx.chain) : undefined;
  const failsafeRound = roundForTime(failsafe, ctx.chain);
  const unlockAt = unlockRound !== undefined ? timeOfRound(unlockRound, ctx.chain) : undefined;
  const failsafeAt = timeOfRound(failsafeRound, ctx.chain);

  // Show exactly what will happen, then ask.
  const items = await Promise.all(inputs.map(describeInput));
  ctx.out("condlock will encrypt and then DELETE these originals:");
  for (const it of items) ctx.out(`  ${it.path}  (${it.summary})`);
  ctx.out(`vault:      ${vaultDir}`);
  if (unlockAt) {
    ctx.out(`unlocks:    ${unlockAt.toISOString()}  (drand round ${unlockRound}, in ${formatSpan(unlockAt.getTime() - now.date.getTime())})`);
  } else {
    const g = nflRule!.game;
    ctx.out(`unlocks:    when ${nflRule!.team} ${nflRule!.outcome === "loss" ? "lose" : "win"} ${g.away} at ${g.home} (kickoff ${g.kickoffAt})`);
    ctx.out(`            tie: ${nflRule!.ifTie}, postponed: ${nflRule!.ifPostponed}, cancelled: ${nflRule!.ifCancelled}`);
  }
  ctx.out(`fail-safe:  ${failsafeAt.toISOString()}  (drand round ${failsafeRound})`);
  if (escrow) ctx.out(`escrow:     ${escrow.url}${values.guardian ? " (key split 2-of-3 with your guardian)" : ""}`);
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
  let sealed: Record<string, any> | undefined;
  try {
    const result = await createVault({ inputs, vaultDir, dek });
    created = true;
    vaultId = result.vaultId;
    entryCount = result.manifest.entries.length;
    await fsp.mkdir(path.join(vaultDir, KEYS_DIR));
    const keys: LockFile["keys"] = { failsafe: `${KEYS_DIR}/${KEY_FILES.failsafe}` };
    if (unlockRound !== undefined) {
      const timelock = await wrapDek({ dek, vaultId, target: { round: unlockRound }, chain: ctx.chain });
      await fsp.writeFile(path.join(vaultDir, KEYS_DIR, KEY_FILES.timelock), serializeTlockEnvelope(timelock), { flag: "wx" });
      keys.timelock = `${KEYS_DIR}/${KEY_FILES.timelock}`;
    }
    const failsafeEnv = await wrapDek({ dek, vaultId, target: { round: failsafeRound }, chain: ctx.chain });
    await fsp.writeFile(path.join(vaultDir, KEYS_DIR, KEY_FILES.failsafe), serializeTlockEnvelope(failsafeEnv), { flag: "wx" });
    // Prove the vault decrypts with this key before anything is sealed or deleted.
    await verifyVault(vaultDir, dek);

    if (escrow) {
      const condition = nflRule ?? { type: "time", unlockAt: unlockAt!.toISOString() };
      const res = await escrow.client.call("POST", "/locks", {
        vaultId,
        condition,
        failsafeAt: failsafeAt.toISOString(),
        dek: Buffer.from(dek).toString("base64"),
        ...(typeof values.guardian === "string" ? { guardian: { recipient: values.guardian } } : {}),
      });
      if (res.status !== 201) throw new Error(`the escrow refused the lock (${res.status} ${res.json.error ?? ""}): ${res.json.message ?? ""}`);
      sealed = res.json;
      if (sealed.guardian?.share) {
        await fsp.writeFile(path.join(vaultDir, KEYS_DIR, GUARDIAN_SHARE_FILE), String(sealed.guardian.share), { flag: "wx" });
        keys.guardianShare = `${KEYS_DIR}/${GUARDIAN_SHARE_FILE}`;
      }
    }
    const lock: LockFile = {
      format: "condlock-lock",
      version: 2,
      vaultId,
      createdAt: new Date().toISOString(),
      condition: nflRule ? { type: "nfl", rule: nflRule as unknown as Record<string, unknown> } : { type: "time", round: unlockRound!, unlockAt: unlockAt!.toISOString() },
      failsafe: { round: failsafeRound, unlockAt: failsafeAt.toISOString() },
      keys,
      vaultHeader: await readVaultHeader(vaultDir),
      ...(escrow && sealed
        ? { escrow: { url: escrow.url, deviceId: escrow.deviceId, keyScheme: String(sealed.keyScheme), conditionSha256: String(sealed.conditionSha256) } }
        : {}),
    };
    await fsp.writeFile(path.join(vaultDir, LOCK_FILE), JSON.stringify(lock, null, 2) + "\n", { flag: "wx" });
  } catch (err) {
    if (created) await fsp.rm(vaultDir, { recursive: true, force: true });
    throw new Error(`lock failed, originals untouched: ${(err as Error).message}`);
  } finally {
    zeroize(dek);
  }

  await appendLog(vaultDir, "locked", {
    vaultId,
    items: entryCount,
    condition: nflRule ? "nfl" : "time",
    ...(unlockRound !== undefined ? { unlockRound, unlockAt: unlockAt!.toISOString() } : {}),
    failsafeRound,
    failsafeAt: failsafeAt.toISOString(),
    drandRoundAtLock: now.round,
    ...(sealed ? { escrow: escrow!.url, keyScheme: sealed.keyScheme, conditionSha256: sealed.conditionSha256 } : {}),
  });

  for (const p of inputs) await fsp.rm(p, { recursive: true });
  await appendLog(vaultDir, "originals-deleted", { items: inputs.length });

  ctx.out(`Locked ${entryCount} item(s) into ${vaultDir}`);
  if (sealed) ctx.out(`Sealed with the escrow (${sealed.keyScheme}); condition sha256 ${sealed.conditionSha256}`);
  if (sealed?.guardian) {
    ctx.out(`Send your guardian ${path.join(vaultDir, KEYS_DIR, GUARDIAN_SHARE_FILE)}. Only their key opens it (age -d -i <their key>),`);
    ctx.out(`and it's only needed if one of the escrow's two key holders is unavailable.`);
  }
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

async function readLockFile(vaultDir: string): Promise<LockFile | null> {
  try {
    return JSON.parse(await fsp.readFile(path.join(vaultDir, LOCK_FILE), "utf8")) as LockFile;
  } catch {
    return null;
  }
}

/** Fields where vault.json differs from the copy kept in lock.json. */
function headerDiff(a: VaultHeader, b: VaultHeader): string[] {
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  return [...keys].filter((k) => JSON.stringify((a as any)[k]) !== JSON.stringify((b as any)[k])).sort();
}

async function cmdUnlock(args: string[], ctx: CliContext): Promise<number> {
  const { values, positionals } = parse(args, { out: { type: "string" }, "guardian-share": { type: "string" } });
  const vaultDir = vaultArg(positionals, ctx);
  await vaultHeader(vaultDir);
  const lock = await readLockFile(vaultDir);
  const envelopes = await readEnvelopes(vaultDir);
  const outDir = path.resolve(ctx.cwd, typeof values.out === "string" ? values.out : path.dirname(vaultDir));

  let dek: Uint8Array | undefined;
  let via: string | undefined;
  const locked: StillLockedError[] = [];
  for (const e of envelopes) {
    try {
      dek = await unwrapDek(e.env, { client: ctx.client });
      via = `${e.name === "failsafe" ? "fail-safe" : "time-lock"} key (drand round ${e.env.round})`;
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

  if (!dek && lock?.escrow) {
    const r = await unlockViaEscrow(vaultDir, lock, ctx, typeof values["guardian-share"] === "string" ? values["guardian-share"] : undefined, locked);
    if (typeof r === "number") return r;
    dek = r.dek;
    via = r.via;
  }

  if (!dek || !via) {
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
    await appendLog(vaultDir, "unlocked", { via, items: restored.length });
    ctx.out(`Unlocked with the ${via}. Restored:`);
    for (const r of restored) ctx.out(`  ${r}`);
    ctx.out(`The vault is still at ${vaultDir}; delete it once you've checked your files.`);
    return EXIT.OK;
  } finally {
    zeroize(dek);
  }
}

/** Ask the escrow. Returns the key, or an exit code after printing why not. */
async function unlockViaEscrow(
  vaultDir: string,
  lock: LockFile,
  ctx: CliContext,
  guardianShareFile: string | undefined,
  locked: StillLockedError[],
): Promise<{ dek: Uint8Array; via: string } | number> {
  // The escrow releases a key once. Don't spend it on a vault whose header can't open.
  if (lock.vaultHeader) {
    const diff = headerDiff(await readVaultHeader(vaultDir), lock.vaultHeader);
    if (diff.length) {
      await appendLog(vaultDir, "unlock-attempt", { result: "vault-header-mismatch", fields: diff });
      ctx.err(`vault.json doesn't match the copy in lock.json (${diff.join(", ")}). Restore it before unlocking:`);
      ctx.err(`the escrow releases the key only once, and it can't open a vault with a damaged header.`);
      return EXIT.ERROR;
    }
  }
  const { client } = await escrowFor(ctx);
  const body = guardianShareFile ? { guardianShare: (await fsp.readFile(path.resolve(ctx.cwd, guardianShareFile), "utf8")).trim() } : undefined;
  let res;
  try {
    res = await client.call("POST", `/locks/${lock.vaultId}/unlock`, body);
  } catch (err) {
    if (err instanceof EscrowUnreachableError) {
      await appendLog(vaultDir, "unlock-attempt", { result: "escrow-unreachable" });
      ctx.err(`${err.message}. Nothing was changed; try again later.`);
      return EXIT.ESCROW_UNAVAILABLE;
    }
    throw err;
  }
  const j = res.json;
  const failsafe = locked.find((l) => l.round === lock.failsafe.round)?.unlockAt.toISOString() ?? lock.failsafe.unlockAt;
  switch (res.status) {
    case 200: {
      await appendLog(vaultDir, "escrow-released", { via: j.via });
      return { dek: new Uint8Array(Buffer.from(String(j.dek), "base64")), via: `escrow (${j.via === "failsafe" ? "fail-safe" : "condition met"}${j.detail?.reason ? `: ${j.detail.reason}` : ""})` };
    }
    case 423:
      await appendLog(vaultDir, "unlock-attempt", { result: "still-locked", escrow: j.reason, resolved: j.resolved ?? false });
      if (lock.condition.type === "time") {
        ctx.out(`still locked until ${String(j.unlockAt ?? lock.condition.unlockAt)}`);
        ctx.out(`  escrow: ${j.reason}`);
      } else {
        ctx.out(`still locked: ${j.reason}`);
      }
      if (j.resolved) ctx.out("  the sealed outcome didn't happen; only the fail-safe opens this vault now");
      ctx.out(`  fail-safe: ${failsafe}`);
      return EXIT.STILL_LOCKED;
    case 409:
      await appendLog(vaultDir, "unlock-attempt", { result: "already-released" });
      ctx.err("The escrow already released this key once; it never releases it again. The fail-safe still opens the vault on its date.");
      return EXIT.ERROR;
    case 401:
      await appendLog(vaultDir, "unlock-attempt", { result: "unauthorized" });
      ctx.err("The escrow rejected this request's signature. If this computer's clock is more than 5 minutes off, fix it; changing it can't unlock anything.");
      return EXIT.ERROR;
    case 503:
      await appendLog(vaultDir, "unlock-attempt", { result: j.error });
      ctx.err(`The escrow can't release the key right now (${j.error}): ${j.message}`);
      if (j.error === "insufficient-shares") {
        ctx.err(`  key holders: ${Object.entries(j.holders ?? {}).map(([k, v]) => `${k} ${String(v)}`).join(", ")}`);
        ctx.err(`  ask your guardian to decrypt ${path.join(vaultDir, lock.keys.guardianShare ?? "keys/guardian-share.age")} and run:`);
        ctx.err(`  condlock unlock ${vaultDir} --guardian-share <file with their output, base64>`);
      }
      return EXIT.ESCROW_UNAVAILABLE;
    default:
      await appendLog(vaultDir, "unlock-attempt", { result: j.error ?? `http-${res.status}` });
      ctx.err(`The escrow refused to release the key (${res.status} ${j.error ?? ""}): ${j.message ?? ""}`);
      return EXIT.ERROR;
  }
}

// ---------- status ----------

async function cmdStatus(args: string[], ctx: CliContext): Promise<number> {
  const { values, positionals } = parse(args, { offline: { type: "boolean" } });
  const vaultDir = vaultArg(positionals, ctx);
  const header = await vaultHeader(vaultDir);
  const lock = (await readLockFile(vaultDir)) as LockFile;
  const envelopes = await readEnvelopes(vaultDir);
  const dataFiles = await fsp.readdir(path.join(vaultDir, "data"));
  let bytes = 0;
  for (const f of dataFiles) bytes += (await fsp.stat(path.join(vaultDir, "data", f))).size;
  const { entries } = await readLog(vaultDir);

  ctx.out(`vault:      ${vaultDir}`);
  ctx.out(`vault ID:   ${header.vaultId}  (format v${header.version}${header.keyCommitment ? ", key-committed" : ""})`);
  ctx.out(`created:    ${lock.createdAt}`);
  ctx.out(`condition:  ${lock.condition.type === "nfl" ? "NFL result" : "time-lock"}`);
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
  if (lock.escrow) {
    try {
      const { client } = await escrowFor(ctx);
      const res = await client.call("GET", `/locks/${lock.vaultId}`);
      if (res.status === 200) {
        const last = res.json.latestVerifierResult?.detail?.reason;
        ctx.out(`escrow:     ${res.json.status} (${res.json.keyScheme})${last ? `; last check: ${last}` : ""}`);
      } else {
        ctx.out(`escrow:     unavailable (${res.status} ${res.json.error ?? ""})`);
      }
    } catch (err) {
      ctx.out(`escrow:     unreachable (${(err as Error).message})`);
    }
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
  const { values, positionals } = parse(args, { server: { type: "boolean" } });
  const vaultDir = vaultArg(positionals, ctx);
  await vaultHeader(vaultDir);
  const { entries, broken } = await readLog(vaultDir);
  for (const e of entries) {
    const detail = Object.entries(e.detail)
      .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`)
      .join(" ");
    ctx.out(`${String(e.seq).padStart(3)}  ${e.at}  ${e.event.padEnd(18)} ${detail}`);
  }
  let code: number = EXIT.OK;
  if (broken) {
    ctx.out(`WARNING: ${LOG_FILE} has been tampered with: ${broken}`);
    code = EXIT.ERROR;
  } else {
    ctx.out(`(${entries.length} entries, chain intact)`);
  }
  if (values.server) {
    const lock = await readLockFile(vaultDir);
    if (!lock?.escrow) throw new Error("this vault isn't sealed with an escrow");
    const { client } = await escrowFor(ctx);
    const res = await client.call("GET", `/locks/${lock.vaultId}/log`);
    if (res.status !== 200) throw new Error(`couldn't read the escrow's log (${res.status} ${res.json.error ?? ""})`);
    ctx.out(`escrow audit log (${lock.escrow.url}, append-only on the server):`);
    for (const e of res.json.entries as { id: number; at: string; event: string; detail: Record<string, unknown> }[]) {
      const d = Object.entries(e.detail)
        .filter(([k]) => k !== "reports")
        .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`)
        .join(" ");
      ctx.out(`${String(e.id).padStart(5)}  ${e.at}  ${e.event.padEnd(18)} ${d}`);
    }
  }
  return code;
}

// ---------- device ----------

async function cmdDevice(args: string[], ctx: CliContext): Promise<number> {
  const [sub, ...rest] = args;
  if (sub === "register") {
    const { values } = parse(rest, { escrow: { type: "string" }, label: { type: "string" } });
    if (typeof values.escrow !== "string") throw new UsageError("device register needs --escrow <url>");
    const url = checkEscrowUrl(values.escrow);
    const token = ctx.env.CONDLOCK_ADMIN_TOKEN;
    if (!token) throw new Error("set CONDLOCK_ADMIN_TOKEN to the escrow's admin token (it's only needed once, to register)");
    if (await loadDevice(ctx.home)) throw new Error(`${path.join(ctx.home, "device.json")} already exists`);
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const raw = publicKey.export({ format: "jwk" }).x!;
    const label = typeof values.label === "string" ? values.label : "condlock CLI";
    const deviceId = await registerDevice({ url, adminToken: token, publicKey: raw, label, fetch: ctx.fetch });
    const file = await saveDevice(ctx.home, {
      format: "condlock-device",
      version: 1,
      escrowUrl: url,
      deviceId,
      publicKey: raw,
      privateKey: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
      label,
    });
    ctx.out(`Registered this computer with ${url} as device ${deviceId}.`);
    ctx.out(`Device key: ${file} (owner-only). It signs requests; it can't open any vault.`);
    return EXIT.OK;
  }
  if (sub === undefined || sub === "show") {
    const d = await loadDevice(ctx.home);
    if (!d) {
      ctx.out("No escrow device registered. Run: condlock device register --escrow <url>");
      return EXIT.OK;
    }
    ctx.out(`escrow:  ${d.escrowUrl}\ndevice:  ${d.deviceId} (${d.label})\nkey:     ${d.publicKey}`);
    return EXIT.OK;
  }
  throw new UsageError(`unknown device command "${sub}"`);
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
