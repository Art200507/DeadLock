/**
 * Cheat attempts against the running stack. Every one must leave the vault locked (nothing
 * restored, the escrow lock not released) and, where the server sees it, leave a trace in the
 * audit log.
 */
import assert from "node:assert/strict";
import { createPrivateKey } from "node:crypto";
import * as fsp from "node:fs/promises";
import * as https from "node:https";
import * as path from "node:path";
import { after, before, describe, it } from "node:test";
import { NodeHttpHandler } from "@smithy/node-http-handler";
import { generateDeviceKeyPair, signRequest } from "@condlock/core";
import {
  AwsKms,
  KeyAccessDeniedError,
  SocketReleaser,
  openGuardianShare,
  pushSecrets,
  type ReleaseRequest,
} from "@condlock/escrow";
import { run, defaultContext } from "../../packages/cli/src/cli.js";
import { ADMIN_TOKEN, KEY_A, PARENT_ROLE_KEY_ID, ROOT, startStack, type Stack } from "../src/stack.js";
import { guardian, newGame, newUser, nflRule, type User } from "../src/users.js";
import { THESPORTSDB_HOST, TEST_APISPORTS_KEY, TEST_THESPORTSDB_KEY } from "../../services/escrow/test/helpers/sports.js";

const MIN = 60_000;
let s: Stack;
let alice: User;
before(async () => {
  s = await startStack();
  alice = await newUser(s, "alice", s.escrowUrl);
});
after(() => s?.stop());

const exists = async (p: string) => (await fsp.stat(p).catch(() => null)) !== null;
const status = async (vaultId: string) => (await s.admin.query<{ status: string }>("select status from locks where vault_id = $1", [vaultId])).rows[0]?.status;
const events = async (vaultId: string) =>
  (await s.admin.query<{ event: string; detail_json: any }>("select event, detail_json from audit_log where vault_id = $1 order by id", [vaultId])).rows;
const lockJson = async (vault: string) => JSON.parse(await fsp.readFile(path.join(vault, "lock.json"), "utf8"));

/** Lock a fresh folder with the escrow; returns the vault, its ID and the original folder path. */
async function timeLock(u: User, name: string, until = "1d", extra: string[] = []) {
  const folder = await u.folder(name);
  const r = await u.cli("lock", name, "--until", until, "--escrow", "--yes", ...extra);
  assert.equal(r.code, 0, r.stdout + r.stderr);
  const vault = `${folder}.condlock`;
  return { folder, vault, vaultId: (await lockJson(vault)).vaultId as string };
}

/** Assert the vault is still locked: non-zero exit, nothing restored, escrow not released. */
async function assertStillLocked(r: { code: number }, v: { folder: string; vaultId: string }) {
  assert.notEqual(r.code, 0, "the unlock must fail");
  assert.equal(await exists(v.folder), false, "nothing was restored");
  assert.ok(["sealed", "met"].includes((await status(v.vaultId))!), "the escrow did not release the key");
}

describe("cheat: move this computer's clock", () => {
  it("a clock days ahead (or behind) opens nothing: tlock ignores it and the escrow rejects the stale signature", async () => {
    const v = await timeLock(alice, "ClockAhead", "2h");
    for (const offset of [2 * 86_400_000, -2 * 86_400_000]) {
      const lines: string[] = [];
      const ctx = {
        ...defaultContext(s.cliEnv(alice.home)),
        cwd: alice.cwd,
        out: (l: string) => lines.push(l),
        err: (l: string) => lines.push(l),
        prompt: async () => "",
        now: () => new Date(Date.now() + offset),
      };
      const code = await run(["unlock", v.vault], ctx);
      await assertStillLocked({ code }, v);
      assert.match(lines.join("\n"), /rejected this request's signature/);
    }
    const failures = (await events(v.vaultId)).filter((e) => e.event === "auth-failed");
    assert.equal(failures.length, 2);
    assert.ok(failures.every((e) => e.detail_json.reason === "stale-or-future-timestamp"));
  });
});

describe("cheat: edit or delete the logs", () => {
  it("editing or deleting the local log is detected and changes nothing", async () => {
    const v = await timeLock(alice, "LocalLog");
    assert.equal((await alice.cli("unlock", v.vault)).code, 2);
    const logFile = path.join(v.vault, "log.jsonl");
    const lines = (await fsp.readFile(logFile, "utf8")).trim().split("\n");
    lines[0] = lines[0]!.replace('"items":1', '"items":0');
    await fsp.writeFile(logFile, lines.join("\n") + "\n");
    const log = await alice.cli("log", v.vault);
    assert.equal(log.code, 1);
    assert.match(log.stdout, /WARNING: log\.jsonl has been tampered with/);
    await fsp.rm(logFile);
    await assertStillLocked(await alice.cli("unlock", v.vault), v);
    // The server's copy is untouched and still shows every attempt.
    const server = await alice.cli("log", v.vault, "--server");
    assert.equal((server.stdout.match(/unlock-requested/g) ?? []).length, 2);
  });

  it("the server log can't be edited, deleted or truncated, and the service role can't remove the guard", async () => {
    const v = await timeLock(alice, "ServerLog");
    const before = (await events(v.vaultId)).length;
    await assert.rejects(s.admin.query("update audit_log set event = 'nothing' where vault_id = $1", [v.vaultId]), /append-only/);
    await assert.rejects(s.admin.query("delete from audit_log where vault_id = $1", [v.vaultId]), /append-only/);
    await assert.rejects(s.admin.query("truncate audit_log"), /append-only/);
    // The production service role (db/roles.sql) can't drop or disable the triggers.
    const roles = (await fsp.readFile(path.join(ROOT, "db/roles.sql"), "utf8")).replace("CHANGE_ME", "e2e-only-password");
    await s.admin.query(roles);
    await s.admin.query("set role condlock_app");
    try {
      await assert.rejects(s.admin.query("drop trigger audit_log_no_update_delete on audit_log"), /owner|permission/);
      await assert.rejects(s.admin.query("alter table audit_log disable trigger all"), /owner|permission/);
      await assert.rejects(s.admin.query("alter table locks disable trigger locks_guard"), /owner|permission/);
      await assert.rejects(s.admin.query("update locks set unlock_at = now() where vault_id = $1", [v.vaultId]), /permission|sealed/);
    } finally {
      await s.admin.query("reset role");
    }
    assert.equal((await events(v.vaultId)).length, before);
  });

  it("even the database owner wiping the log doesn't unlock anything", async () => {
    const v = await timeLock(alice, "OwnerWipe");
    await s.admin.query("alter table audit_log disable trigger audit_log_no_update_delete");
    try {
      await s.admin.query("delete from audit_log where vault_id = $1", [v.vaultId]);
    } finally {
      await s.admin.query("alter table audit_log enable trigger audit_log_no_update_delete");
    }
    await assertStillLocked(await alice.cli("unlock", v.vault), v);
    assert.ok((await events(v.vaultId)).some((e) => e.event === "unlock-denied"), "new attempts are logged again");
  });
});

describe("cheat: replay or forge a signed request", () => {
  it("replayed, forged, re-pathed, body-swapped, stale and unknown-device requests are all rejected", async () => {
    const v = await timeLock(alice, "Replay");
    const dev = JSON.parse(await fsp.readFile(path.join(alice.home, "device.json"), "utf8"));
    const key = createPrivateKey({ key: Buffer.from(dev.privateKey, "base64"), format: "der", type: "pkcs8" });
    const p = `/locks/${v.vaultId}/unlock`;
    const send = (headers: Record<string, string>, body = "", at = p) =>
      fetch(s.escrowUrl + at, { method: "POST", headers: { ...headers, "content-type": "application/json" }, body });

    const good = signRequest({ deviceId: dev.deviceId, privateKey: key, method: "POST", path: p, body: "" });
    assert.equal((await send(good)).status, 423, "a genuine request is answered (still locked)");
    assert.equal((await send(good)).status, 401, "the same request replayed");
    const forged = signRequest({ deviceId: dev.deviceId, privateKey: generateDeviceKeyPair().privateKey, method: "POST", path: p, body: "" });
    assert.equal((await send(forged)).status, 401, "signed by another key");
    const other = signRequest({ deviceId: dev.deviceId, privateKey: key, method: "POST", path: `/locks/${v.vaultId}`, body: "" });
    assert.equal((await send(other)).status, 401, "signature moved to another path");
    const swapped = signRequest({ deviceId: dev.deviceId, privateKey: key, method: "POST", path: p, body: "" });
    assert.equal((await send(swapped, JSON.stringify({ guardianShare: "AAAA" }))).status, 401, "body changed after signing");
    const stale = signRequest({ deviceId: dev.deviceId, privateKey: key, method: "POST", path: p, body: "", timestamp: Date.now() - 10 * MIN });
    assert.equal((await send(stale)).status, 401, "stale timestamp");
    const stranger = generateDeviceKeyPair();
    assert.equal((await send(signRequest({ deviceId: "not-a-registered-dev", privateKey: stranger.privateKey, method: "POST", path: p, body: "" }))).status, 401);
    // Registering a new device needs the admin token.
    const reg = await fetch(`${s.escrowUrl}/devices`, { method: "POST", headers: { authorization: "Bearer guess", "content-type": "application/json" }, body: JSON.stringify({ publicKey: stranger.publicKey }) });
    assert.equal(reg.status, 401);
    assert.notEqual(ADMIN_TOKEN, "guess");

    const reasons = (await events(v.vaultId)).filter((e) => e.event === "auth-failed").map((e) => e.detail_json.reason).sort();
    assert.deepEqual(reasons, ["bad-signature", "bad-signature", "bad-signature", "replayed-nonce", "stale-or-future-timestamp", "unknown-device"].sort());
    assert.equal(await status(v.vaultId), "sealed");
  });
});

describe("cheat: swap the lock's terms after sealing", () => {
  it("editing lock.json or the tlock key's round locally opens nothing", async () => {
    const v = await timeLock(alice, "LocalTerms");
    const lock = await lockJson(v.vault);
    const nowRound = s.drand.latestRound;
    lock.condition.round = nowRound;
    lock.condition.unlockAt = s.drandNow().toISOString();
    await fsp.writeFile(path.join(v.vault, "lock.json"), JSON.stringify(lock));
    const envFile = path.join(v.vault, "keys", "timelock.json");
    const env = JSON.parse(await fsp.readFile(envFile, "utf8"));
    env.round = nowRound;
    env.unlockAt = s.drandNow().toISOString();
    await fsp.writeFile(envFile, JSON.stringify(env));
    await assertStillLocked(await alice.cli("unlock", v.vault), v);
  });

  it("a database owner who rewrites the sealed condition (triggers off) gets nothing: the seal is in the KMS context", async () => {
    const v = await timeLock(alice, "DbTerms");
    const past = new Date(s.drandNow().getTime() - MIN).toISOString();
    await s.admin.query("alter table locks disable trigger locks_guard");
    try {
      await s.admin.query(
        "update locks set condition_json = jsonb_set(condition_json, '{unlockAt}', to_jsonb($2::text)), unlock_at = $2::timestamptz where vault_id = $1",
        [v.vaultId, past],
      );
    } finally {
      await s.admin.query("alter table locks enable trigger locks_guard");
    }
    const r = await alice.cli("unlock", v.vault);
    await assertStillLocked(r, v);
    assert.match(r.stderr, /refused to release the key \(500 unwrap-failed\)/);
    assert.ok((await events(v.vaultId)).some((e) => e.event === "unlock-failed" && e.detail_json.reason === "unwrap-failed"));
  });

  it("moving one vault's wrapped key onto another vault's row doesn't open either", async () => {
    const a = await timeLock(alice, "SwapA", "3m");
    const b = await timeLock(alice, "SwapB", "1d");
    s.drandAt(s.drandNow().getTime() + 4 * MIN);
    await fsp.rm(path.join(a.vault, "keys", "timelock.json")); // force the escrow path
    await s.admin.query("alter table locks disable trigger locks_guard");
    try {
      await s.admin.query("update locks set wrapped_dek = (select wrapped_dek from locks where vault_id = $2) where vault_id = $1", [a.vaultId, b.vaultId]);
    } finally {
      await s.admin.query("alter table locks enable trigger locks_guard");
    }
    await assertStillLocked(await alice.cli("unlock", a.vault), a);
  });
});

describe("cheat: a non-approved enclave build asks for the key", () => {
  it("a modified verifier image (wrong PCR0) with the parent's credentials is refused by KMS; the approved one isn't", async () => {
    const v = await timeLock(alice, "RogueEnclave", "2m");
    s.drandAt(s.drandNow().getTime() + 3 * MIN); // the condition is now met
    const rogue = await s.startVerifier({ pcr0: "cd".repeat(48), name: "rogue-verifier" });
    // The parent operator hands the rogue image everything it has.
    await pushSecrets({ path: rogue.socket }, {
      v: 1,
      op: "secrets",
      aws: { accessKeyId: PARENT_ROLE_KEY_ID, secretAccessKey: "e2e-not-a-secret", sessionToken: "e2e-session-token" },
      sports: { apiSportsKey: TEST_APISPORTS_KEY, theSportsDbKey: TEST_THESPORTSDB_KEY },
    });
    const row = (await s.admin.query<any>("select condition_json, failsafe_at, wrapped_dek from locks where vault_id = $1", [v.vaultId])).rows[0];
    const latest = s.drand.beacon(s.drand.latestRound);
    const req: ReleaseRequest = {
      v: 1,
      vaultId: v.vaultId,
      condition: row.condition_json,
      failsafeAt: new Date(row.failsafe_at).toISOString(),
      wrappedDek: row.wrapped_dek,
      evidence: { drandBeacon: latest },
    };
    const res = await new SocketReleaser({ path: rogue.socket }).release(req);
    assert.equal(res.ok, false);
    assert.equal(!res.ok && res.code, "access-denied");
    assert.ok(s.kms.calls.some((c) => c.keyId === KEY_A && c.op === "Decrypt" && c.outcome === "AccessDeniedException"));

    // Control: the same request to the approved image would be granted (it's stateless; nothing is marked released).
    const ok = await new SocketReleaser({ path: s.verifierSocket }).release(req);
    assert.equal(ok.ok, true);
    assert.equal(await status(v.vaultId), "sealed");
    await rogue.proc.stop();
  });

  it("the API host calling KMS Decrypt directly (no attestation) is refused", async () => {
    const v = await timeLock(alice, "DirectKms");
    const row = (await s.admin.query<any>("select wrapped_dek, condition_json, failsafe_at from locks where vault_id = $1", [v.vaultId])).rows[0];
    const { sealHash, parseCondition } = await import("@condlock/escrow");
    const seal = sealHash({ vaultId: v.vaultId, condition: parseCondition(row.condition_json), failsafeAt: row.failsafe_at });
    const host = new AwsKms({
      keyId: KEY_A,
      region: "us-east-1",
      endpoint: s.kmsEndpoint,
      credentials: { accessKeyId: PARENT_ROLE_KEY_ID, secretAccessKey: "e2e-not-a-secret" },
      requestHandler: new NodeHttpHandler({ httpsAgent: new https.Agent({ ca: s.caPem }) }),
    });
    await assert.rejects(host.unwrap(row.wrapped_dek, { vaultId: v.vaultId, seal }), KeyAccessDeniedError);
  });
});

describe("cheat: the sports sources", () => {
  let bob: User;
  before(async () => (bob = await newUser(s, "bob", s.escrowUrl)));

  async function nflLock(name: string) {
    const game = newGame(s, new Date(s.drandNow().getTime() + 10 * MIN));
    const folder = await bob.folder(name);
    const rule = await bob.writeJson(`${name}.json`, nflRule(game));
    const r = await bob.cli("lock", name, "--nfl", rule, "--yes");
    assert.equal(r.code, 0, r.stdout + r.stderr);
    const vault = `${folder}.condlock`;
    s.drandAt(game.kickoffAt.getTime() + 4 * 60 * MIN);
    return { game, folder, vault, vaultId: (await lockJson(vault)).vaultId as string };
  }

  it("one source lying about the score, or both disagreeing, keeps it locked", async () => {
    const v = await nflLock("Liar");
    for (const [what, patch] of [
      ["scores differ (TheSportsDB says the Bills lost)", { apiStatus: "FT", tsdbStatus: "FT", homeScore: 27, awayScore: 20, tsdbHomeScore: 20, tsdbAwayScore: 27 }],
      ["final vs postponed", { apiStatus: "FT", tsdbStatus: "Postponed", homeScore: 27, awayScore: 20, tsdbHomeScore: undefined, tsdbAwayScore: undefined }],
      ["TheSportsDB links a different API-Sports game", { apiStatus: "FT", tsdbStatus: "FT", tsdbLinksApiSportsId: "1" }],
      ["API-Sports says final, TheSportsDB still in Q4", { apiStatus: "FT", tsdbStatus: "Q4", tsdbLinksApiSportsId: undefined }],
    ] as const) {
      s.sports.update(v.game.apiSportsId, patch as any);
      const r = await bob.cli("unlock", v.vault);
      assert.equal(r.code, 2, `${what}: ${r.stdout}${r.stderr}`);
      await assertStillLocked(r, v);
    }
    const checks = (await events(v.vaultId)).filter((e) => e.event === "verifier-check");
    assert.equal(checks.filter((e) => e.detail_json.disagree).length, 3, "three disagreements recorded with both reports");
    assert.ok(checks.every((e) => e.detail_json.reports?.length === 2 || !e.detail_json.disagree));
  });

  it("sources down or unreachable means 'try later', never a release", async () => {
    const v = await nflLock("Outage");
    v.game.score("FT", "FT", 27, 20); // a real win...
    s.sports.down.apiSports = true; // ...but one source is down
    try {
      const r = await bob.cli("unlock", v.vault);
      assert.equal(r.code, 5, r.stdout + r.stderr);
      assert.match(r.stderr, /sources-unavailable/);
      await assertStillLocked(r, v);
    } finally {
      s.sports.down.apiSports = false;
    }
    s.keyA.down = true; // KMS down
    try {
      const r = await bob.cli("unlock", v.vault);
      assert.equal(r.code, 5, r.stdout + r.stderr);
      await assertStillLocked(r, v);
    } finally {
      s.keyA.down = false;
    }
    // TheSportsDB unreachable at the network level (the parent's proxy for it stops).
    await s.forwarders[THESPORTSDB_HOST]!.close();
    const r = await bob.cli("unlock", v.vault);
    assert.equal(r.code, 5, r.stdout + r.stderr);
    await assertStillLocked(r, v);
  });
});

describe("cheat: use only one of the 2-of-3 shares", () => {
  it("no single share releases, the guardian's share doesn't skip the condition, and any two do release", async () => {
    const carol = await newUser(s, "carol", s.splitUrl);
    const g = await guardian();
    const v = await timeLock(carol, "Split", "3m", ["--guardian", g.recipient]);
    const share = await openGuardianShare(await fsp.readFile(path.join(v.vault, "keys", "guardian-share.age"), "utf8"), g.identity);
    const shareFile = path.join(carol.cwd, "share.b64");
    await fsp.writeFile(shareFile, Buffer.from(share).toString("base64"));
    await fsp.rm(path.join(v.vault, "keys", "timelock.json")); // only the escrow route

    let r = await carol.cli("unlock", v.vault, "--guardian-share", shareFile);
    assert.equal(r.code, 2, "the guardian's share before the time: still locked");
    s.drandAt(s.drandNow().getTime() + 4 * MIN);

    s.keyB.down = true;
    try {
      r = await carol.cli("unlock", v.vault);
      assert.equal(r.code, 5);
      assert.match(r.stderr, /escrow-kms ok, second-provider unavailable, guardian not-provided/);
      s.keyA.down = true;
      r = await carol.cli("unlock", v.vault, "--guardian-share", shareFile);
      assert.equal(r.code, 5, "the guardian's share alone");
      assert.match(r.stderr, /escrow-kms unavailable, second-provider unavailable, guardian ok/);
      s.keyB.down = false;
      r = await carol.cli("unlock", v.vault);
      assert.equal(r.code, 5, "the second provider's share alone");
      await assertStillLocked(r, v);
    } finally {
      s.keyA.down = s.keyB.down = false;
    }
    r = await carol.cli("unlock", v.vault);
    assert.equal(r.code, 0, "both providers: released");
    assert.ok(await exists(v.folder));
  });
});

describe("cheat: tamper with the vault header", () => {
  it("before the time: still locked; after: the CLI refuses to spend the one release on a damaged header", async () => {
    const v = await timeLock(alice, "Header", "3m");
    const headerFile = path.join(v.vault, "vault.json");
    const original = await fsp.readFile(headerFile, "utf8");
    const h = JSON.parse(original);
    await fsp.writeFile(headerFile, JSON.stringify({ ...h, chunkSize: 4096 }));
    await assertStillLocked(await alice.cli("unlock", v.vault), v);

    s.drandAt(s.drandNow().getTime() + 4 * MIN);
    // The local tlock key now opens, but the key commitment refuses the edited header.
    let r = await alice.cli("unlock", v.vault);
    await assertStillLocked(r, v);
    assert.match(r.stderr, /key commitment/);
    // Via the escrow: refused before asking, so the release isn't wasted.
    await fsp.rename(path.join(v.vault, "keys", "timelock.json"), path.join(alice.cwd, "timelock.json.bak"));
    const asked = (await events(v.vaultId)).filter((e) => e.event === "unlock-requested").length;
    r = await alice.cli("unlock", v.vault);
    await assertStillLocked(r, v);
    assert.match(r.stderr, /vault\.json doesn't match the copy in lock\.json \(chunkSize\)/);
    assert.equal((await events(v.vaultId)).filter((e) => e.event === "unlock-requested").length, asked);
    // A forged commitment (edited in both files) gets the key released once, and still opens nothing.
    await fsp.writeFile(headerFile, JSON.stringify({ ...h, keyCommitment: "ab".repeat(32) }));
    const lock = await lockJson(v.vault);
    lock.vaultHeader.keyCommitment = "ab".repeat(32);
    await fsp.writeFile(path.join(v.vault, "lock.json"), JSON.stringify(lock));
    r = await alice.cli("unlock", v.vault);
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /key commitment/);
    assert.equal(await exists(v.folder), false, "nothing restored");
    // Restoring the real header gets the files back (here with the local tlock key).
    await fsp.writeFile(headerFile, original);
    await fsp.rename(path.join(alice.cwd, "timelock.json.bak"), path.join(v.vault, "keys", "timelock.json"));
    assert.equal((await alice.cli("unlock", v.vault)).code, 0);
  });
});
