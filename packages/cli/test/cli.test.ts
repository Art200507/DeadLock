/**
 * CLI tests, fully offline: a mocked drand network decides when rounds exist. Every file
 * these tests create or delete lives under one fresh temp directory.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as fsp from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { after, afterEach, before, describe, it, mock } from "node:test";
import { fileURLToPath } from "node:url";
import { parseTlockEnvelope, timeOfRound } from "@condlock/core";
import { MockDrand } from "../../core/test/helpers/mock-drand.js";
import { CONFIRM_WORD, EXIT, assertSafeToDelete, run } from "../src/cli.js";
import { formatSpan, parseDuration, parseWhen } from "../src/time.js";
import { allFiles, exists, hashTree, makeCtx, makeMixedFolder } from "./helpers/fixtures.js";

let work: string;
before(async () => {
  work = await fsp.mkdtemp(path.join(tmpdir(), "condlock-cli-test-"));
});
after(async () => {
  await fsp.rm(work, { recursive: true, force: true });
});
afterEach(() => mock.restoreAll());

/** A fresh subdirectory of the temp dir, and a mock drand that has published round 1000. */
async function scene(name: string) {
  const dir = path.join(work, name);
  await fsp.mkdir(dir);
  const drand = new MockDrand();
  drand.publish(1000);
  const ctx = (answers: string[] = []) => makeCtx({ cwd: dir, client: drand, chain: drand.chainParams, answers });
  return { dir, drand, ctx };
}

const ROUNDS_PER_MINUTE = 20; // 3-second rounds

describe("condlock lock → unlock, mixed folder, mocked drand", () => {
  let dir: string;
  let drand: MockDrand;
  let ctxFor: (a?: string[]) => ReturnType<typeof makeCtx>;
  let original: Map<string, string>;
  let folder: string;
  let vault: string;
  let lockCtx: ReturnType<typeof makeCtx>;

  before(async () => {
    ({ dir, drand, ctx: ctxFor } = await scene("main"));
    folder = await makeMixedFolder(path.join(dir, "Holiday"));
    original = await hashTree(folder);
    vault = `${folder}.condlock`;
  });

  it("lock shows what will be deleted, asks for a typed confirmation, then locks", async () => {
    lockCtx = ctxFor([CONFIRM_WORD]);
    const code = await run(["lock", "Holiday", "--until", "1m"], lockCtx);
    assert.equal(code, EXIT.OK, lockCtx.text());
    const out = lockCtx.text();
    assert.match(out, /will encrypt and then DELETE these originals/);
    assert.ok(out.includes(folder), "lists the folder being deleted");
    assert.match(out, /folder, 4 file\(s\)/);
    assert.equal(lockCtx.prompts.length, 1);
    assert.match(lockCtx.prompts[0]!, /Type "delete"/);
  });

  it("deletes the originals after locking", async () => {
    assert.equal(await exists(folder), false);
    assert.deepEqual((await fsp.readdir(dir)).sort(), ["Holiday.condlock"]);
  });

  it("prints the copies checklist", () => {
    const out = lockCtx.text();
    for (const place of ["iCloud Photos", "Google Photos", "Time Machine", "Downloads", "WhatsApp", "Messages"]) {
      assert.ok(out.includes(place), `checklist mentions ${place}`);
    }
  });

  it("writes a time-lock and a 1-year fail-safe envelope at the right drand rounds", async () => {
    const tl = parseTlockEnvelope(await fsp.readFile(path.join(vault, "keys", "timelock.json"), "utf8"));
    const fs = parseTlockEnvelope(await fsp.readFile(path.join(vault, "keys", "failsafe.json"), "utf8"));
    assert.equal(tl.round, 1000 + ROUNDS_PER_MINUTE);
    assert.equal(tl.chain.hash, drand.info.hash);
    const year = (365 * 86_400) / 3;
    assert.equal(fs.round, 1000 + year);
    assert.equal(fs.unlockAt, timeOfRound(1000 + year, drand.chainParams).toISOString());
  });

  it("never writes the data key to disk, and zeroes it after use", async () => {
    assert.equal(lockCtx.keysIssued.length, 1);
    const { copy, live } = lockCtx.keysIssued[0]!;
    assert.ok(live.every((b) => b === 0), "live key buffer is zeroed");
    const needles = [Buffer.from(copy), Buffer.from(Buffer.from(copy).toString("hex")), Buffer.from(Buffer.from(copy).toString("base64"))];
    for (const f of await allFiles(vault)) {
      const bytes = await fsp.readFile(f);
      for (const n of needles) assert.equal(bytes.indexOf(n), -1, `key material found in ${f}`);
    }
  });

  it("unlock before the round is published says still locked and restores nothing", async () => {
    drand.publish(1000 + ROUNDS_PER_MINUTE - 1);
    // Even with the laptop clock pushed a century ahead.
    mock.method(Date, "now", () => Date.UTC(2126, 0, 1));
    const c = ctxFor();
    const code = await run(["unlock", "Holiday.condlock"], c);
    assert.equal(code, EXIT.STILL_LOCKED);
    const tl = parseTlockEnvelope(await fsp.readFile(path.join(vault, "keys", "timelock.json"), "utf8"));
    assert.equal(c.lines[0], `still locked until ${tl.unlockAt}`);
    assert.match(c.text(), /1 more round\(s\), about 3s/);
    assert.deepEqual(await fsp.readdir(dir), ["Holiday.condlock"]);
  });

  it("status reports the lock and how far drand has to go", async () => {
    const c = ctxFor();
    assert.equal(await run(["status", vault], c), EXIT.OK);
    const out = c.text();
    assert.match(out, /condition: {2}time-lock/);
    assert.match(out, /contents: {3}1 encrypted item\(s\)/);
    assert.match(out, /names are encrypted/);
    assert.match(out, /state: {6}locked; drand is at round 1019, 1 round\(s\) to go/);
    assert.ok(!out.includes("beach.jpg"), "status shows no file names");
  });

  it("unlock after the round restores everything byte for byte", async () => {
    drand.publish(1000 + ROUNDS_PER_MINUTE);
    // And with the laptop clock set back to 1970.
    mock.method(Date, "now", () => 0);
    const c = ctxFor();
    const code = await run(["unlock", vault], c);
    assert.equal(code, EXIT.OK, c.text());
    assert.match(c.text(), /Unlocked with the time-lock key/);
    assert.deepEqual(await hashTree(folder), original);
  });

  it("log shows every event with an intact hash chain", async () => {
    const c = ctxFor();
    assert.equal(await run(["log", vault], c), EXIT.OK);
    const events = c.lines.filter((l) => /^\s*\d+ /.test(l)).map((l) => l.trim().split(/\s+/)[2]);
    assert.deepEqual(events, ["locked", "originals-deleted", "unlock-attempt", "unlocked"]);
    assert.match(c.text(), /4 entries, chain intact/);
    assert.ok(!c.text().includes("beach.jpg"), "log shows no file names");
  });

  it("log detects an edited entry", async () => {
    const f = path.join(vault, "log.jsonl");
    const lines = (await fsp.readFile(f, "utf8")).trimEnd().split("\n");
    lines[2] = lines[2]!.replace("still-locked", "opened");
    await fsp.writeFile(f, lines.join("\n") + "\n");
    const c = ctxFor();
    assert.equal(await run(["log", vault], c), EXIT.ERROR);
    assert.match(c.text(), /tampered with: line 4/);
  });
});

describe("condlock lock: safety and validation", () => {
  it("declining the confirmation changes nothing", async () => {
    const { dir, ctx } = await scene("decline");
    const folder = await makeMixedFolder(path.join(dir, "Stuff"), 1024);
    const before = await hashTree(folder);
    for (const answer of ["", "no", "DELETE", "yes"]) {
      const c = ctx([answer]);
      assert.equal(await run(["lock", "Stuff", "--until", "10m"], c), EXIT.CANCELLED);
      assert.match(c.text(), /Cancelled\. Nothing was changed\./);
      assert.equal(c.keysIssued.length, 0, "no key was even generated");
    }
    assert.deepEqual(await hashTree(folder), before);
    assert.deepEqual(await fsp.readdir(dir), ["Stuff"]);
  });

  it("rejects bad times and fail-safes without touching anything", async () => {
    const { dir, ctx } = await scene("validation");
    const file = path.join(dir, "a.txt");
    await fsp.writeFile(file, "keep me");
    const cases: [string[], RegExp][] = [
      [["--until", "10m", "--failsafe", "10d"], /at least 30 days/],
      [["--until", "60d", "--failsafe", "40d"], /can't be earlier than the unlock time/],
      [["--until", "2001-01-01T00:00Z"], /not in the future/],
      [["--until", "2030-01-01T09:00"], /no time zone/],
      [["--until", "soon"], /can't read "soon"/],
      [[], /needs --until/],
    ];
    for (const [flags, re] of cases) {
      const c = ctx();
      assert.equal(await run(["lock", "a.txt", "--yes", ...flags], c), EXIT.ERROR, flags.join(" "));
      assert.match(c.text(), re);
    }
    assert.equal(await fsp.readFile(file, "utf8"), "keep me");
    assert.deepEqual(await fsp.readdir(dir), ["a.txt"]);
  });

  it("refuses to put the vault inside what it locks", async () => {
    const { dir, ctx } = await scene("inside");
    await fsp.mkdir(path.join(dir, "box"));
    await fsp.writeFile(path.join(dir, "box", "x"), "x");
    const c = ctx();
    assert.equal(await run(["lock", "box", "--until", "1h", "--vault", "box/v.condlock", "--yes"], c), EXIT.ERROR);
    assert.match(c.text(), /can't be inside what it locks/);
    assert.equal(await fsp.readFile(path.join(dir, "box", "x"), "utf8"), "x");
  });

  it("refuses the filesystem root and the home folder (checked without running a lock)", () => {
    assert.throws(() => assertSafeToDelete("/", "/Users/someone"), /filesystem root/);
    assert.throws(() => assertSafeToDelete("/Users/someone", "/Users/someone"), /home folder/);
    assert.throws(() => assertSafeToDelete("/Users", "/Users/someone"), /home folder/);
    assert.doesNotThrow(() => assertSafeToDelete("/Users/someone/Pictures/x", "/Users/someone"));
  });

  it("locks several inputs into one vault with --vault and an absolute time", async () => {
    const { dir, drand, ctx } = await scene("multi");
    await fsp.writeFile(path.join(dir, "one.bin"), "1");
    await fsp.writeFile(path.join(dir, "two.bin"), "22");
    const target = timeOfRound(1000 + 100, drand.chainParams).toISOString();
    const c = ctx();
    assert.equal(await run(["lock", "one.bin", "two.bin", "--until", target, "--vault", "both.condlock", "--yes"], c), EXIT.OK, c.text());
    assert.deepEqual((await fsp.readdir(dir)).sort(), ["both.condlock"]);
    drand.publish(1100);
    const u = ctx();
    assert.equal(await run(["unlock", "both.condlock"], u), EXIT.OK, u.text());
    assert.equal(await fsp.readFile(path.join(dir, "one.bin"), "utf8"), "1");
    assert.equal(await fsp.readFile(path.join(dir, "two.bin"), "utf8"), "22");
  });
});

describe("condlock unlock: fail-safe and drand outages", () => {
  it("opens with the fail-safe key when only that envelope is left", async () => {
    const { dir, drand, ctx } = await scene("failsafe");
    await fsp.writeFile(path.join(dir, "secret.txt"), "hello");
    assert.equal(await run(["lock", "secret.txt", "--until", "40d", "--failsafe", "50d", "--yes"], ctx()), EXIT.OK);
    const vault = path.join(dir, "secret.txt.condlock");
    await fsp.rm(path.join(vault, "keys", "timelock.json")); // the main key is lost
    const fs = parseTlockEnvelope(await fsp.readFile(path.join(vault, "keys", "failsafe.json"), "utf8"));
    const c = ctx();
    assert.equal(await run(["unlock", vault], c), EXIT.STILL_LOCKED);
    assert.equal(c.lines[0], `still locked until ${fs.unlockAt}`);
    drand.publish(fs.round);
    const u = ctx();
    assert.equal(await run(["unlock", vault], u), EXIT.OK, u.text());
    assert.match(u.text(), /Unlocked with the fail-safe key/);
    assert.equal(await fsp.readFile(path.join(dir, "secret.txt"), "utf8"), "hello");
  });

  it("says it can't tell when drand is unreachable, and restores nothing", async () => {
    const { dir, drand, ctx } = await scene("outage");
    await fsp.writeFile(path.join(dir, "f.txt"), "x");
    assert.equal(await run(["lock", "f.txt", "--until", "1m", "--yes"], ctx()), EXIT.OK);
    drand.publish(5000);
    drand.offline = true;
    const c = ctx();
    assert.equal(await run(["unlock", "f.txt.condlock"], c), EXIT.DRAND_UNAVAILABLE);
    assert.match(c.text(), /Can't tell whether it's unlocked/);
    assert.deepEqual(await fsp.readdir(dir), ["f.txt.condlock"]);
    const s = ctx();
    assert.equal(await run(["status", "f.txt.condlock"], s), EXIT.OK);
    assert.match(s.text(), /unknown \(couldn't reach drand\)/);
  });

  it("warns and uses the local clock for durations only when drand is down at lock time", async () => {
    const { dir, drand, ctx } = await scene("lock-offline");
    await fsp.writeFile(path.join(dir, "f.txt"), "x");
    drand.offline = true;
    const c = ctx();
    assert.equal(await run(["lock", "f.txt", "--until", "1h", "--yes"], c), EXIT.OK, c.text());
    assert.match(c.text(), /couldn't reach drand, so durations are measured from this computer's clock/);
  });
});

describe("time parsing", () => {
  it("reads durations", () => {
    assert.equal(parseDuration("10m"), 600_000);
    assert.equal(parseDuration("2d"), 2 * 86_400_000);
    assert.equal(parseDuration("1h30m"), 5_400_000);
    assert.equal(parseDuration("1y"), 365 * 86_400_000);
    assert.equal(parseDuration("90s"), 90_000);
    for (const bad of ["", "10", "m", "1.5h", "-1d", "0m", "2027-01-01"]) assert.equal(parseDuration(bad), null, bad);
  });

  it("reads absolute times only with a zone, and bare dates as UTC midnight", () => {
    const now = new Date("2026-01-01T00:00:00Z");
    assert.equal(parseWhen("2027-01-01T09:00Z", now).toISOString(), "2027-01-01T09:00:00.000Z");
    assert.equal(parseWhen("2027-01-01T10:00:00+01:00", now).toISOString(), "2027-01-01T09:00:00.000Z");
    assert.equal(parseWhen("2027-01-01", now).toISOString(), "2027-01-01T00:00:00.000Z");
    assert.equal(parseWhen("10m", now).toISOString(), "2026-01-01T00:10:00.000Z");
    assert.throws(() => parseWhen("2027-01-01T09:00", now), /no time zone/);
  });

  it("formats spans", () => {
    assert.equal(formatSpan(3_725_000), "1h 2m");
    assert.equal(formatSpan(90_000), "1m 30s");
    assert.equal(formatSpan(400 * 86_400_000), "1y 35d");
  });
});

describe("the condlock binary", () => {
  const cliDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const bin = (...args: string[]) =>
    spawnSync(process.execPath, ["--import", "tsx", "--conditions=development", "src/index.ts", ...args], {
      cwd: cliDir,
      encoding: "utf8",
      env: { ...process.env, CONDLOCK_OFFLINE: "1" },
    });

  it("prints usage and exits 0 for --help", () => {
    const r = bin("--help");
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /condlock lock <path\.\.\.> --until/);
  });

  it("exits 1 with usage for an unknown command", () => {
    const r = bin("frobnicate");
    assert.equal(r.status, 1);
    assert.match(r.stderr, /unknown command "frobnicate"/);
  });
});
