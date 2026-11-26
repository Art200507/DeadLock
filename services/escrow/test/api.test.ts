import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { conditionHash, parseCondition } from "../src/conditions.js";
import { KeyServiceError } from "../src/keywrap/types.js";
import { SIG_HEADERS, generateDeviceKeyPair, signRequest } from "../src/signing.js";
import { DAY_MS, TEST_ADMIN_TOKEN, b64, harness, newDek, timeLockBody, vaultId, type Harness } from "./helpers.js";

async function events(h: Harness, vault: string) {
  const { rows } = await h.db.query<{ event: string; detail_json: Record<string, unknown> }>(
    "select event, detail_json from audit_log where vault_id = $1 order by id",
    [vault],
  );
  return rows;
}

const NFL = {
  type: "nfl",
  gameId: "12345",
  scheduledAt: "2026-12-07T18:00:00Z",
  team: "Buffalo Bills",
  outcome: "win",
  ifTie: "stay-locked",
  ifPostponed: "stay-locked",
};

describe("device registration", () => {
  let h: Harness;
  before(async () => (h = await harness()));
  after(() => h.close());

  it("needs the admin token", async () => {
    const res = await h.app.request("/devices", {
      method: "POST",
      headers: { authorization: "Bearer wrong", "content-type": "application/json" },
      body: JSON.stringify({ publicKey: generateDeviceKeyPair().publicKey }),
    });
    assert.equal(res.status, 401);
    assert.equal((await h.app.request("/devices", { method: "POST", body: "{}" })).status, 401);
  });

  it("rejects malformed and duplicate keys, and audits registrations", async () => {
    const post = (body: unknown) =>
      h.app.request("/devices", { method: "POST", headers: { authorization: `Bearer ${TEST_ADMIN_TOKEN}` }, body: JSON.stringify(body) });
    assert.equal((await post({ publicKey: "short" })).status, 400);
    const kp = generateDeviceKeyPair();
    assert.equal((await post({ publicKey: kp.publicKey })).status, 201);
    assert.equal((await post({ publicKey: kp.publicKey })).status, 409);
    const { rows } = await h.db.query("select 1 from audit_log where vault_id is null and event = 'device-registered'");
    assert.ok(rows.length >= 2);
  });
});

describe("signed requests", () => {
  let h: Harness;
  let vault: string;
  before(async () => {
    h = await harness();
    const body = timeLockBody(h);
    vault = body.vaultId;
    assert.equal((await h.call("POST", "/locks", body)).status, 201);
  });
  after(() => h.close());

  it("accepts a correctly signed request", async () => {
    assert.equal((await h.call("GET", `/locks/${vault}`)).status, 200);
  });

  it("rejects missing, forged, altered, stale and replayed signatures", async () => {
    const p = `/locks/${vault}`;
    assert.equal((await h.app.request(p)).status, 401, "no headers");
    const cases: [string, Parameters<Harness["call"]>[3]][] = [
      ["bad signature", { tamper: (hd) => (hd[SIG_HEADERS.signature] = Buffer.alloc(64).toString("base64")) }],
      ["unknown device", { tamper: (hd) => (hd[SIG_HEADERS.device] = "unknown-device-123") }],
      ["altered timestamp", { tamper: (hd) => (hd[SIG_HEADERS.timestamp] = String(Number(hd[SIG_HEADERS.timestamp]) + 1)) }],
      ["altered nonce", { tamper: (hd) => (hd[SIG_HEADERS.nonce] = "0".repeat(32)) }],
      ["stale timestamp (6 min old by the server clock)", { timestamp: h.clock.now.getTime() - 6 * 60_000 }],
      ["future timestamp (6 min ahead)", { timestamp: h.clock.now.getTime() + 6 * 60_000 }],
    ];
    for (const [name, o] of cases) assert.equal((await h.call("GET", p, undefined, o)).status, 401, name);

    const nonce = "ab".repeat(16);
    assert.equal((await h.call("GET", p, undefined, { nonce })).status, 200);
    assert.equal((await h.call("GET", p, undefined, { nonce })).status, 401, "replayed nonce");

    const reasons = (await events(h, vault)).filter((e) => e.event === "auth-failed").map((e) => e.detail_json.reason);
    for (const r of ["bad-signature", "unknown-device", "stale-or-future-timestamp", "replayed-nonce"]) {
      assert.ok(reasons.includes(r), `audited ${r}`);
    }
  });

  it("rejects a body swapped after signing, and a signature moved to another path", async () => {
    const signed = JSON.stringify(timeLockBody(h));
    const headers = signRequest({ deviceId: h.device.deviceId, privateKey: h.device.privateKey, method: "POST", path: "/locks", body: signed, timestamp: h.clock.now.getTime() });
    const swapped = await h.app.request("/locks", { method: "POST", headers, body: JSON.stringify(timeLockBody(h)) });
    assert.equal(swapped.status, 401);
    const forGet = signRequest({ deviceId: h.device.deviceId, privateKey: h.device.privateKey, method: "GET", path: `/locks/${vault}`, timestamp: h.clock.now.getTime() });
    const moved = await h.app.request(`/locks/${vault}/log`, { headers: forGet });
    assert.equal(moved.status, 401);
  });

  it("only the device's own key can sign", async () => {
    const imposter = { ...h.device, privateKey: generateDeviceKeyPair().privateKey };
    assert.equal((await h.call("GET", `/locks/${vault}`, undefined, { device: imposter })).status, 401);
  });
});

describe("POST /locks", () => {
  let h: Harness;
  before(async () => (h = await harness()));
  after(() => h.close());

  it("seals a lock, wraps the key and never stores or returns it raw", async () => {
    const dek = newDek();
    const body = timeLockBody(h, { dek: b64(dek) });
    const res = await h.call("POST", "/locks", body);
    assert.equal(res.status, 201, JSON.stringify(res.json));
    assert.equal(res.json.status, "sealed");
    assert.equal(res.json.vaultId, body.vaultId);
    assert.equal(res.json.conditionSha256, conditionHash(parseCondition(body.condition)));
    assert.equal(res.json.failsafeAt, body.failsafeAt);
    assert.equal(res.json.latestVerifierResult, null);
    assert.ok(!JSON.stringify(res.json).includes(b64(dek)), "response has no key");

    const needles = [b64(dek), Buffer.from(dek).toString("hex"), Buffer.from(dek).toString("base64url")];
    for (const table of ["locks", "audit_log", "devices", "request_nonces"]) {
      const dump = JSON.stringify((await h.db.query(`select * from ${table}`)).rows);
      for (const n of needles) assert.ok(!dump.includes(n), `raw key found in ${table}`);
    }
    const { rows } = await h.db.query<{ wrapped_dek: { scheme: string } }>("select wrapped_dek from locks where vault_id = $1", [body.vaultId]);
    assert.equal(rows[0]!.wrapped_dek.scheme, "mock-kms/v1");
    assert.deepEqual((await events(h, body.vaultId)).map((e) => e.event), ["lock-created"]);
  });

  it("refuses a second lock for the same vault", async () => {
    const body = timeLockBody(h);
    assert.equal((await h.call("POST", "/locks", body)).status, 201);
    const again = await h.call("POST", "/locks", { ...body, dek: b64(newDek()) });
    assert.equal(again.status, 409);
    assert.equal(again.json.error, "lock-exists");
  });

  it("validates the request against the server clock", async () => {
    const now = h.clock.now.getTime();
    const bad: [string, Record<string, unknown>, string][] = [
      ["fail-safe < 30 days", { failsafeAt: new Date(now + 29 * DAY_MS).toISOString() }, "bad-failsafe"],
      ["fail-safe > 10 years", { failsafeAt: new Date(now + 11 * 365 * DAY_MS).toISOString() }, "bad-failsafe"],
      ["fail-safe before unlock", { condition: { type: "time", unlockAt: new Date(now + 400 * DAY_MS).toISOString() } }, "bad-failsafe"],
      ["unlock in the past", { condition: { type: "time", unlockAt: new Date(now - 1000).toISOString() } }, "bad-condition"],
      ["non-UTC time", { condition: { type: "time", unlockAt: "2027-01-01T09:00:00+01:00" } }, "bad-condition"],
      ["extra condition field", { condition: { type: "time", unlockAt: new Date(now + 1e6).toISOString(), note: "x" } }, "bad-condition"],
      ["unknown condition type", { condition: { type: "vibes" } }, "bad-condition"],
      ["short key", { dek: b64(new Uint8Array(16)) }, "bad-request"],
      ["bad vault id", { vaultId: "ABC" }, "bad-request"],
    ];
    for (const [name, override, code] of bad) {
      const res = await h.call("POST", "/locks", timeLockBody(h, override));
      assert.equal(res.status, 400, name);
      assert.equal(res.json.error, code, name);
    }
    assert.equal((await h.call("POST", "/locks", undefined, { rawBody: "not json" })).status, 400);
    assert.equal((await h.call("POST", "/locks", undefined, { rawBody: JSON.stringify({ pad: "x".repeat(20_000) }) })).status, 400);
  });

  it("accepts an NFL condition and seals its exact rules", async () => {
    const res = await h.call("POST", "/locks", timeLockBody(h, { condition: NFL }));
    assert.equal(res.status, 201, JSON.stringify(res.json));
    assert.equal(res.json.condition.team, "Buffalo Bills");
    assert.equal(res.json.unlockAt, null);
    assert.equal(res.json.conditionSha256, conditionHash(parseCondition(NFL)));
  });

  it("stores nothing when the key service is down", async () => {
    const down = await harness({
      kms: {
        scheme: "mock-kms/v1",
        wrap: async () => {
          throw new KeyServiceError("down");
        },
        unwrap: async () => new Uint8Array(),
      },
    });
    try {
      const res = await down.call("POST", "/locks", timeLockBody(down));
      assert.equal(res.status, 503);
      assert.equal((await down.db.query("select 1 from locks")).rows.length, 0);
    } finally {
      await down.close();
    }
  });
});

describe("GET /locks/:id and /log", () => {
  let h: Harness;
  before(async () => (h = await harness()));
  after(() => h.close());

  it("shows status, condition and the latest verifier result", async () => {
    const body = timeLockBody(h);
    await h.call("POST", "/locks", body);
    await h.escrow.recordVerifierCheck(body.vaultId, { verifier: "time", result: "not-yet", check: 1 });
    await h.escrow.recordVerifierCheck(body.vaultId, { verifier: "time", result: "not-yet", check: 2 });
    const res = await h.call("GET", `/locks/${body.vaultId}`);
    assert.equal(res.status, 200);
    assert.equal(res.json.status, "sealed");
    assert.equal(res.json.condition.type, "time");
    assert.equal(res.json.unlockAt, body.condition.unlockAt);
    assert.equal(res.json.latestVerifierResult.detail.check, 2);
  });

  it("404s for unknown or malformed IDs", async () => {
    assert.equal((await h.call("GET", `/locks/${vaultId()}`)).status, 404);
    assert.equal((await h.call("GET", "/locks/not-a-vault")).status, 404);
    assert.equal((await h.call("GET", `/locks/${vaultId()}/log`)).status, 404);
  });

  it("has no route that edits or deletes a lock", async () => {
    const body = timeLockBody(h);
    await h.call("POST", "/locks", body);
    for (const method of ["PUT", "PATCH", "DELETE"]) {
      assert.equal((await h.call(method, `/locks/${body.vaultId}`, { condition: { type: "time", unlockAt: "2026-12-01T12:00:01Z" } })).status, 404, method);
    }
    for (const p of [`/locks/${body.vaultId}/condition`, `/locks/${body.vaultId}/release`, `/locks/${body.vaultId}/met`]) {
      assert.equal((await h.call("POST", p, {})).status, 404, p);
    }
    assert.equal((await h.call("GET", `/locks/${body.vaultId}`)).json.status, "sealed");
  });
});

describe("POST /locks/:id/unlock (verifier decides from drand, API enforces once)", () => {
  let h: Harness;
  before(async () => (h = await harness()));
  after(() => h.close());

  it("says still locked before drand reaches the unlock round, even if the server clock is ahead", async () => {
    const body = timeLockBody(h);
    await h.call("POST", "/locks", body);
    // Server clock jumps 2 hours, drand doesn't: the API's clock can't release anything.
    const t0 = h.clock.now;
    h.clock.now = new Date(t0.getTime() + 2 * 3_600_000);
    const res = await h.call("POST", `/locks/${body.vaultId}/unlock`, undefined, { timestamp: h.clock.now.getTime() });
    h.clock.now = t0;
    assert.equal(res.status, 423);
    assert.equal(res.json.message, "still locked");
    assert.match(res.json.reason, /condition not met yet: unlocks at drand round \d+/);
    assert.equal(res.json.failsafeAt, body.failsafeAt);
    assert.ok(!("dek" in res.json));
    assert.deepEqual((await events(h, body.vaultId)).map((e) => e.event), ["lock-created", "unlock-requested", "unlock-denied"]);
    assert.equal((await h.call("GET", `/locks/${body.vaultId}`)).json.status, "sealed");
  });

  it("releases the key exactly once when drand reaches the unlock round", async () => {
    const dek = newDek();
    const body = timeLockBody(h, { dek: b64(dek) });
    await h.call("POST", "/locks", body);
    h.setTime(new Date(body.condition.unlockAt).getTime() + 3000);
    const res = await h.call("POST", `/locks/${body.vaultId}/unlock`);
    assert.equal(res.status, 200, JSON.stringify(res.json));
    assert.equal(res.json.via, "condition");
    assert.equal(res.json.dek, b64(dek));
    const view = await h.call("GET", `/locks/${body.vaultId}`);
    assert.equal(view.json.status, "released");
    assert.ok(view.json.releasedAt);

    const again = await h.call("POST", `/locks/${body.vaultId}/unlock`);
    assert.equal(again.status, 409);
    assert.equal(again.json.error, "already-released");

    const log = await h.call("GET", `/locks/${body.vaultId}/log`);
    assert.deepEqual(
      log.json.entries.map((e: { event: string }) => e.event),
      ["lock-created", "unlock-requested", "released", "unlock-requested", "unlock-denied"],
    );
    assert.ok(!JSON.stringify(log.json).includes(b64(dek)), "log has no key");
    assert.equal(typeof log.json.entries[2].detail.drandRound, "number", "release records the drand round used");
  });

  it("an NFL lock waits for its verifier, and a recorded 'met' alone doesn't release it", async () => {
    const body = timeLockBody(h, { condition: NFL });
    await h.call("POST", "/locks", body);
    await h.escrow.recordConditionMet(body.vaultId, { note: "milestone 5 verifier would put evidence here" });
    const res = await h.call("POST", `/locks/${body.vaultId}/unlock`);
    assert.equal(res.status, 423);
    assert.match(res.json.reason, /waiting for the nfl verifier/);
  });

  it("releases via the fail-safe once drand reaches the fail-safe round", async () => {
    const dek = newDek();
    const body = timeLockBody(h, { condition: NFL, dek: b64(dek) });
    await h.call("POST", "/locks", body);
    h.setTime(new Date(body.failsafeAt).getTime() - 10_000);
    assert.equal((await h.call("POST", `/locks/${body.vaultId}/unlock`)).status, 423);
    h.setTime(new Date(body.failsafeAt).getTime() + 3000);
    const res = await h.call("POST", `/locks/${body.vaultId}/unlock`);
    assert.equal(res.status, 200, JSON.stringify(res.json));
    assert.equal(res.json.via, "failsafe");
    assert.equal(res.json.dek, b64(dek));
    assert.equal((await h.call("GET", `/locks/${body.vaultId}`)).json.status, "failsafe");
    assert.equal((await h.call("POST", `/locks/${body.vaultId}/unlock`)).status, 409);
  });

  it("concurrent unlocks release the key exactly once", async () => {
    const body = timeLockBody(h, { condition: { type: "time", unlockAt: new Date(h.clock.now.getTime() + 60_000).toISOString() } });
    await h.call("POST", "/locks", body);
    h.setTime(h.clock.now.getTime() + 120_000);
    const results = await Promise.all(Array.from({ length: 5 }, () => h.call("POST", `/locks/${body.vaultId}/unlock`)));
    assert.equal(results.filter((r) => r.status === 200).length, 1);
    assert.equal(results.filter((r) => r.status === 409).length, 4);
  });

  it("any registered device of the account may unlock; others may not", async () => {
    const body = timeLockBody(h, { condition: { type: "time", unlockAt: new Date(h.clock.now.getTime() + 60_000).toISOString() } });
    await h.call("POST", "/locks", body);
    h.setTime(h.clock.now.getTime() + 120_000);
    const stranger = { ...generateDeviceKeyPair(), deviceId: "not-registered-1" };
    assert.equal((await h.call("POST", `/locks/${body.vaultId}/unlock`, undefined, { device: stranger })).status, 401);
    const phone = await h.registerDevice("phone");
    assert.equal((await h.call("POST", `/locks/${body.vaultId}/unlock`, undefined, { device: phone })).status, 200);
  });

  it("a wrapped key copied into another vault's row won't unwrap (vault ID + seal in the context)", async () => {
    const a = timeLockBody(h);
    await h.call("POST", "/locks", a);
    const { rows } = await h.db.query<{ wrapped_dek: unknown }>("select wrapped_dek from locks where vault_id = $1", [a.vaultId]);
    // Someone with database access forges vault B with A's wrapped key and an already-passed time.
    const b = vaultId();
    await h.db.query(
      `insert into locks (vault_id, condition_json, condition_sha256, wrapped_dek, failsafe_at, created_by_device)
       values ($1, '{"type":"time","unlockAt":"2026-01-01T00:00:00.000Z"}', repeat('0', 64), $2::jsonb, now() + interval '60 days', $3)`,
      [b, JSON.stringify(rows[0]!.wrapped_dek), h.device.deviceId],
    );
    const res = await h.call("POST", `/locks/${b}/unlock`);
    assert.equal(res.status, 500);
    assert.equal(res.json.error, "unwrap-failed");
    assert.ok(!("dek" in res.json));
    assert.deepEqual((await events(h, b)).map((e) => e.event), ["unlock-requested", "unlock-failed"]);
    assert.equal((await h.call("GET", `/locks/${b}`)).json.status, "sealed", "status unchanged on failure");
  });

  it("reports drand or verifier outages as 503 and changes nothing", async () => {
    const body = timeLockBody(h);
    await h.call("POST", "/locks", body);
    h.drand.offline = true;
    const r1 = await h.call("POST", `/locks/${body.vaultId}/unlock`);
    h.drand.offline = false;
    assert.equal(r1.status, 503);
    assert.equal(r1.json.error, "drand-unavailable");

    const broken = await harness({ releaser: { release: async () => Promise.reject(new Error("socket closed")) } });
    try {
      const b2 = timeLockBody(broken);
      await broken.call("POST", "/locks", b2);
      const r2 = await broken.call("POST", `/locks/${b2.vaultId}/unlock`);
      assert.equal(r2.status, 503);
      assert.equal(r2.json.error, "verifier-unavailable");
      assert.equal((await broken.call("GET", `/locks/${b2.vaultId}`)).json.status, "sealed");
    } finally {
      await broken.close();
    }
  });
});
