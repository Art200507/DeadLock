/**
 * End to end, as deployed: lock real folders with the condlock CLI, delete the originals, and
 * get them back on time and on an NFL result, through the escrow API, Postgres, the enclave
 * verifier, KMS (attestation-bound), the sports providers and drand.
 */
import assert from "node:assert/strict";
import * as fsp from "node:fs/promises";
import * as path from "node:path";
import { after, before, describe, it } from "node:test";
import { openGuardianShare } from "@condlock/escrow";
import { hashTree, startStack, PARENT_ROLE_KEY_ID, KEY_A, KEY_B, type Stack } from "../src/stack.js";
import { guardian, newGame, newUser, nflRule, type User } from "../src/users.js";

const MIN = 60_000;
let s: Stack;
let alice: User;
before(async () => {
  s = await startStack();
  alice = await newUser(s, "alice", s.escrowUrl);
});
after(() => s?.stop());

const gone = async (p: string) => (await fsp.stat(p).catch(() => null)) === null;
const serverLog = async (vaultId: string) =>
  (await s.admin.query<{ event: string; detail_json: any }>("select event, detail_json from audit_log where vault_id = $1 order by id", [vaultId])).rows;
const lockOf = async (vault: string) => JSON.parse(await fsp.readFile(path.join(vault, "lock.json"), "utf8"));

describe("time-lock through the CLI and the escrow", () => {
  it("locks a real folder, deletes the originals, stays locked, then restores it byte for byte", async () => {
    const folder = await alice.folder("Holiday");
    const before = await hashTree(folder);
    const lock = await alice.cli("lock", "Holiday", "--until", "10m", "--escrow", "--yes");
    assert.equal(lock.code, 0, lock.stdout + lock.stderr);
    assert.match(lock.stdout, /Sealed with the escrow \(aws-kms\/v1\)/);
    assert.match(lock.stdout, /Photos app and iCloud Photos/);
    assert.ok(await gone(folder), "originals deleted");
    const vault = `${folder}.condlock`;
    const { vaultId } = await lockOf(vault);

    let res = await alice.cli("unlock", vault);
    assert.equal(res.code, 2, res.stdout + res.stderr);
    assert.match(res.stdout, /still locked until/);
    assert.ok(await gone(folder));

    s.drandAt(s.drandNow().getTime() + 11 * MIN);
    res = await alice.cli("unlock", vault);
    assert.equal(res.code, 0, res.stdout + res.stderr);
    assert.deepEqual(await hashTree(folder), before, "restored byte for byte");
    const status = await alice.cli("status", vault);
    assert.match(status.stdout, /format v2, key-committed/);
    assert.match(status.stdout, /escrow: +sealed/, "opened by its own tlock key; the escrow copy was never needed");
    assert.ok((await serverLog(vaultId)).some((e) => e.event === "unlock-denied" && e.detail_json.reason === "still-locked"));
  });

  it("with the local tlock key lost, the escrow releases it on time, once", async () => {
    const folder = await alice.folder("Exams");
    const before = await hashTree(folder);
    assert.equal((await alice.cli("lock", "Exams", "--until", "5m", "--escrow", "--yes")).code, 0);
    const vault = `${folder}.condlock`;
    await fsp.rm(path.join(vault, "keys", "timelock.json"));
    assert.equal((await alice.cli("unlock", vault)).code, 2);

    s.drandAt(s.drandNow().getTime() + 6 * MIN);
    const res = await alice.cli("unlock", vault);
    assert.equal(res.code, 0, res.stdout + res.stderr);
    assert.match(res.stdout, /escrow \(condition met\)/);
    assert.deepEqual(await hashTree(folder), before);
    const log = await alice.cli("log", vault, "--server");
    assert.match(log.stdout, /released .*via=condition/);
    // The verifier, not the API host, did the decrypt: attested, with the relayed role credentials.
    const decrypts = s.kms.calls.filter((c) => c.op === "Decrypt" && c.outcome === "ok");
    assert.ok(decrypts.length > 0 && decrypts.every((c) => c.recipient && c.accessKeyId === PARENT_ROLE_KEY_ID && c.keyId === KEY_A));
    assert.ok(s.kms.calls.filter((c) => c.op === "Encrypt").every((c) => !c.recipient));
  });
});

describe("NFL result through the CLI, the verifier and both sports providers", () => {
  it("stays locked before kickoff and during the game, then opens when the Bills win", async () => {
    const game = newGame(s, new Date(s.drandNow().getTime() + 60 * MIN));
    const folder = await alice.folder("Trophies");
    const before = await hashTree(folder);
    const rule = await alice.writeJson("bills-win.json", nflRule(game));
    const lock = await alice.cli("lock", "Trophies", "--nfl", rule, "--yes");
    assert.equal(lock.code, 0, lock.stdout + lock.stderr);
    assert.match(lock.stdout, /when Buffalo Bills win Miami Dolphins at Buffalo Bills/);
    assert.ok(await gone(folder));
    const vault = `${folder}.condlock`;

    let res = await alice.cli("unlock", vault);
    assert.equal(res.code, 2);
    assert.match(res.stdout, /hasn't kicked off/);

    s.drandAt(game.kickoffAt.getTime() + 90 * MIN);
    game.score("Q3", "Q3", 17, 10);
    res = await alice.cli("unlock", vault);
    assert.equal(res.code, 2);
    assert.match(res.stdout, /in-progress/);

    game.score("FT", "FT", 27, 20);
    res = await alice.cli("unlock", vault);
    assert.equal(res.code, 0, res.stdout + res.stderr);
    assert.match(res.stdout, /Buffalo Bills won as sealed/);
    assert.deepEqual(await hashTree(folder), before);

    const status = await alice.cli("status", vault);
    assert.match(status.stdout, /escrow: +released/);
    const log = await alice.cli("log", vault, "--server");
    assert.match(log.stdout, /verifier-check .*outcome=met/);
  });

  it("2-of-3: shares a + b release normally; with the second provider down, the guardian's share completes it", async () => {
    const bob = await newUser(s, "bob", s.splitUrl);
    const g = await guardian();
    const game = newGame(s, new Date(s.drandNow().getTime() + 30 * MIN));
    const rule = await bob.writeJson("rule.json", nflRule(game));

    const f1 = await bob.folder("Photos2026");
    const h1 = await hashTree(f1);
    const l1 = await bob.cli("lock", "Photos2026", "--nfl", rule, "--guardian", g.recipient, "--yes");
    assert.equal(l1.code, 0, l1.stdout + l1.stderr);
    assert.match(l1.stdout, /Sealed with the escrow \(shamir-2of3\/v1\)/);
    assert.match(l1.stdout, /Send your guardian/);
    const f2 = await bob.folder("Videos2026");
    const h2 = await hashTree(f2);
    assert.equal((await bob.cli("lock", "Videos2026", "--nfl", rule, "--guardian", g.recipient, "--yes")).code, 0);

    s.drandAt(game.kickoffAt.getTime() + 4 * 60 * MIN);
    game.score("AOT", "FT", 30, 27);
    let res = await bob.cli("unlock", `${f1}.condlock`);
    assert.equal(res.code, 0, res.stdout + res.stderr);
    assert.deepEqual(await hashTree(f1), h1);
    assert.ok(s.kms.calls.some((c) => c.keyId === KEY_B && c.op === "Decrypt" && c.outcome === "ok"), "share b came from the second provider");

    s.keyB.down = true;
    try {
      res = await bob.cli("unlock", `${f2}.condlock`);
      assert.equal(res.code, 5, res.stdout + res.stderr);
      assert.match(res.stderr, /insufficient-shares/);
      assert.match(res.stderr, /second-provider unavailable/);
      // The guardian opens their share with their own key and sends back the result.
      const armored = await fsp.readFile(path.join(`${f2}.condlock`, "keys", "guardian-share.age"), "utf8");
      const share = await openGuardianShare(armored, g.identity);
      const shareFile = path.join(bob.cwd, "from-guardian.b64");
      await fsp.writeFile(shareFile, Buffer.from(share).toString("base64"));
      res = await bob.cli("unlock", `${f2}.condlock`, "--guardian-share", shareFile);
      assert.equal(res.code, 0, res.stdout + res.stderr);
      assert.deepEqual(await hashTree(f2), h2);
    } finally {
      s.keyB.down = false;
    }
  });

  // Last: moves drand past a fail-safe, and drand never runs backwards.
  it("a loss stays locked for good; the vault still opens on its fail-safe date, with no escrow needed", async () => {
    const game = newGame(s, new Date(s.drandNow().getTime() + 10 * MIN));
    const folder = await alice.folder("Bet");
    const before = await hashTree(folder);
    const rule = await alice.writeJson("bills-win-2.json", nflRule(game));
    assert.equal((await alice.cli("lock", "Bet", "--nfl", rule, "--failsafe", "31d", "--yes")).code, 0);
    const vault = `${folder}.condlock`;
    s.drandAt(game.kickoffAt.getTime() + 4 * 60 * MIN);
    game.score("FT", "FT", 10, 24);
    let res = await alice.cli("unlock", vault);
    assert.equal(res.code, 2);
    assert.match(res.stdout, /only the fail-safe opens/);

    const { failsafe } = await lockOf(vault);
    s.drandAt(Date.parse(failsafe.unlockAt) + 10_000);
    for (const p of s.procs) if (p.name.startsWith("escrow")) p.child.kill("SIGSTOP"); // the escrow is gone
    try {
      res = await alice.cli("unlock", vault);
      assert.equal(res.code, 0, res.stdout + res.stderr);
      assert.match(res.stdout, /fail-safe key/);
      assert.deepEqual(await hashTree(folder), before);
    } finally {
      for (const p of s.procs) if (p.name.startsWith("escrow")) p.child.kill("SIGCONT");
    }
  });
});
