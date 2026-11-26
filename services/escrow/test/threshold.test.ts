/**
 * 2-of-3 key split: Shamir shares held by (a) the enclave-bound escrow KMS key, (b) an
 * independent second provider, also enclave-bound here, and (c) a guardian's age key. Any two
 * rebuild the data key, none alone does, and the condition is still checked before any unwrap.
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, before, describe, it } from "node:test";
import * as age from "age-encryption";
import { MockKms, MockKmsService, MockNsm } from "../src/keywrap/mock-kms.js";
import {
  GUARDIAN_SHARE_LEN,
  InsufficientSharesError,
  THRESHOLD_SCHEME,
  ThresholdKeyWrapper,
  openGuardianShare,
  parseThresholdParams,
} from "../src/keywrap/threshold.js";
import { KeyServiceError, KeyWrapRegistry, UnwrapError, WrapInputError, type KeyWrapper, type WrappedKey } from "../src/keywrap/types.js";
import { ENCLAVE_PCR0, b64, harness, newDek, timeLockBody, vaultId, type Harness } from "./helpers.js";

const ctx = () => ({ vaultId: vaultId(), seal: randomBytes(32).toString("hex") });

async function guardianKeys() {
  const identity = await age.generateX25519Identity();
  return { identity, recipient: await age.identityToRecipient(identity) };
}

/** A wrapper that can be switched off, to simulate a provider outage. */
class Switchable implements KeyWrapper {
  down = false;
  constructor(private readonly inner: KeyWrapper) {}
  get scheme() {
    return this.inner.scheme;
  }
  wrap(pt: Uint8Array, c: Parameters<KeyWrapper["wrap"]>[1]) {
    return this.inner.wrap(pt, c);
  }
  unwrap(w: WrappedKey, c: Parameters<KeyWrapper["unwrap"]>[1]) {
    if (this.down) return Promise.reject(new KeyServiceError("provider unreachable"));
    return this.inner.unwrap(w, c);
  }
}

describe("2-of-3 split (unit)", () => {
  const a = new MockKms();
  const b = new MockKms({ scheme: "mock-second-provider/v1" });
  const t = new ThresholdKeyWrapper({ escrowKms: a, secondProvider: b });

  it("any two shares rebuild the key; the guardian can open theirs with age", async () => {
    const g = await guardianKeys();
    const c = ctx();
    const dek = newDek();
    const w = await t.wrap(dek, c, { guardianRecipient: g.recipient });
    assert.equal(w.scheme, THRESHOLD_SCHEME);
    const p = parseThresholdParams(w);
    assert.equal(p.shares[2].recipient, g.recipient);
    assert.match(p.shares[2].age, /^-----BEGIN AGE ENCRYPTED FILE-----/);
    assert.ok(!JSON.stringify(w).includes(Buffer.from(dek).toString("base64")) && !JSON.stringify(w).includes(Buffer.from(dek).toString("hex")));

    const guardianShare = await openGuardianShare(p.shares[2].age, g.identity);
    assert.equal(guardianShare.length, GUARDIAN_SHARE_LEN);

    // a + b
    assert.deepEqual(await t.unwrap(w, c), dek);
    // a + c (b down), b + c (a down)
    const aOnly = new ThresholdKeyWrapper({ escrowKms: a, secondProvider: Object.assign(new Switchable(b), { down: true }) });
    assert.deepEqual(await aOnly.unwrap(w, c, { guardianShare }), dek);
    const bOnly = new ThresholdKeyWrapper({ escrowKms: Object.assign(new Switchable(a), { down: true }), secondProvider: b });
    assert.deepEqual(await bOnly.unwrap(w, c, { guardianShare }), dek);
  });

  it("no single holder can rebuild it", async () => {
    const g = await guardianKeys();
    const c = ctx();
    const w = await t.wrap(newDek(), c, { guardianRecipient: g.recipient });
    const guardianShare = await openGuardianShare(parseThresholdParams(w).shares[2].age, g.identity);
    const down = (x: KeyWrapper) => Object.assign(new Switchable(x), { down: true });

    const onlyA = new ThresholdKeyWrapper({ escrowKms: a, secondProvider: down(b) });
    await assert.rejects(onlyA.unwrap(w, c), (e: InsufficientSharesError) =>
      e instanceof InsufficientSharesError && e.holders["escrow-kms"] === "ok" && e.holders["second-provider"] === "unavailable" && e.holders.guardian === "not-provided",
    );
    await assert.rejects(new ThresholdKeyWrapper({ escrowKms: down(a), secondProvider: b }).unwrap(w, c), InsufficientSharesError);
    await assert.rejects(new ThresholdKeyWrapper({ escrowKms: down(a), secondProvider: down(b) }).unwrap(w, c, { guardianShare }), InsufficientSharesError);
  });

  it("shares are bound to the vault and the terms", async () => {
    const g = await guardianKeys();
    const c = ctx();
    const w = await t.wrap(newDek(), c, { guardianRecipient: g.recipient });
    const guardianShare = await openGuardianShare(parseThresholdParams(w).shares[2].age, g.identity);
    // Edited terms: every share refuses (KMS context for a and b, the age header for c).
    await assert.rejects(t.unwrap(w, { ...c, seal: "00".repeat(32) }, { guardianShare }), (e: InsufficientSharesError) =>
      e instanceof InsufficientSharesError && e.holders["escrow-kms"] === "refused" && e.holders.guardian === "invalid",
    );
    // A guardian share from another vault doesn't count.
    const other = ctx();
    const w2 = await t.wrap(newDek(), other, { guardianRecipient: g.recipient });
    const otherShare = await openGuardianShare(parseThresholdParams(w2).shares[2].age, g.identity);
    const aOnly = new ThresholdKeyWrapper({ escrowKms: a, secondProvider: Object.assign(new Switchable(b), { down: true }) });
    await assert.rejects(aOnly.unwrap(w, c, { guardianShare: otherShare }), (e: InsufficientSharesError) => e.holders?.guardian === "invalid");
  });

  it("a corrupted share is caught by the commitment instead of yielding a wrong key", async () => {
    const g = await guardianKeys();
    const c = ctx();
    const w = await t.wrap(newDek(), c, { guardianRecipient: g.recipient });
    const share = await openGuardianShare(parseThresholdParams(w).shares[2].age, g.identity);
    share[60]! ^= 0x01; // inside the Shamir share, after the vault/seal header
    const aOnly = new ThresholdKeyWrapper({ escrowKms: a, secondProvider: Object.assign(new Switchable(b), { down: true }) });
    await assert.rejects(aOnly.unwrap(w, c, { guardianShare: share }), (e: Error) => e instanceof UnwrapError && !(e instanceof InsufficientSharesError) && /don't rebuild/.test(e.message));
    // With all three, the bad one is skipped.
    assert.equal((await t.unwrap(w, c, { guardianShare: share })).length, 32);
  });

  it("requires a valid guardian public key", async () => {
    await assert.rejects(t.wrap(newDek(), ctx()), WrapInputError);
    await assert.rejects(t.wrap(newDek(), ctx(), { guardianRecipient: "age1notarealkey" }), WrapInputError);
  });

  it("accepts a post-quantum hybrid guardian key (age1pq...)", async () => {
    const identity = await age.generateHybridIdentity();
    const recipient = await age.identityToRecipient(identity);
    const c = ctx();
    const dek = newDek();
    const w = await t.wrap(dek, c, { guardianRecipient: recipient });
    const share = await openGuardianShare(parseThresholdParams(w).shares[2].age, identity);
    const aOnly = new ThresholdKeyWrapper({ escrowKms: a, secondProvider: Object.assign(new Switchable(b), { down: true }) });
    assert.deepEqual(await aOnly.unwrap(w, c, { guardianShare: share }), dek);
  });
});

describe("2-of-3 locks end to end (both providers enclave-bound, verifier over a socket)", () => {
  let h: Harness;
  let kmsService: MockKmsService;
  let secondService: MockKmsService;
  let secondInEnclave: Switchable;
  let kmsInEnclave: Switchable;
  let g: { identity: string; recipient: string };

  before(async () => {
    g = await guardianKeys();
    const root = MockNsm.newRoot();
    // Two independent key services, each with a policy that only lets the attested image decrypt.
    kmsService = new MockKmsService({ policy: { requireAttestedPcr0: ENCLAVE_PCR0 }, attestationRoot: root.publicKey });
    secondService = new MockKmsService({ policy: { requireAttestedPcr0: ENCLAVE_PCR0 }, attestationRoot: root.publicKey });
    const nsm = new MockNsm(ENCLAVE_PCR0, root.privateKey);
    const apiKms = new MockKms({ service: kmsService });
    const apiSecond = new MockKms({ service: secondService, scheme: "mock-second-provider/v1" });
    kmsInEnclave = new Switchable(new MockKms({ service: kmsService, attestation: nsm }));
    secondInEnclave = new Switchable(new MockKms({ service: secondService, attestation: nsm, scheme: "mock-second-provider/v1" }));
    h = await harness({
      socket: true,
      // API side: wraps (Encrypt only). Single-key MockKms stays registered for old locks.
      apiKeys: new KeyWrapRegistry(new ThresholdKeyWrapper({ escrowKms: apiKms, secondProvider: apiSecond }), [apiKms]),
      verifierKeys: new KeyWrapRegistry(new ThresholdKeyWrapper({ escrowKms: kmsInEnclave, secondProvider: secondInEnclave }), [kmsInEnclave]),
    });
  });
  after(() => h.close());

  const create = async (dek = newDek()) => {
    const body = { ...timeLockBody(h, { dek: b64(dek) }), guardian: { recipient: g.recipient } };
    const res = await h.call("POST", "/locks", body);
    assert.equal(res.status, 201, JSON.stringify(res.json));
    return { body, res, dek };
  };

  it("creating a split lock returns the guardian's encrypted share; nothing stored opens alone", async () => {
    const { res, body } = await create();
    assert.equal(res.json.keyScheme, THRESHOLD_SCHEME);
    assert.equal(res.json.guardian.recipient, g.recipient);
    assert.match(res.json.guardian.share, /BEGIN AGE ENCRYPTED FILE/);
    const { rows } = await h.db.query<{ wrapped_dek: WrappedKey }>("select wrapped_dek from locks where vault_id = $1", [body.vaultId]);
    assert.ok(!JSON.stringify(rows[0]!.wrapped_dek).includes(body.dek));
    const p = parseThresholdParams(rows[0]!.wrapped_dek);
    assert.deepEqual(p.shares.map((x) => x.holder), ["escrow-kms", "second-provider", "guardian"]);
    // The API host can't decrypt either provider's share: both policies need the enclave's attestation.
    await assert.rejects(new MockKms({ service: kmsService }).unwrap(p.shares[0].wrapped, { vaultId: body.vaultId, seal: "0".repeat(64) }));
    await assert.rejects(
      new MockKms({ service: secondService, scheme: "mock-second-provider/v1" }).unwrap(p.shares[1].wrapped, { vaultId: body.vaultId, seal: "0".repeat(64) }),
      /attestation/,
    );
    const { status } = await h.call("POST", "/locks", { ...timeLockBody(h), guardian: { recipient: "not-an-age-key" } });
    assert.equal(status, 400);
    assert.equal((await h.call("POST", "/locks", timeLockBody(h))).json.error, "bad-guardian", "a split escrow needs a guardian");
  });

  it("normal release: the condition is checked first, then shares a + b", async () => {
    const { body, dek } = await create();
    const decrypts = () => kmsService.calls.decrypt + secondService.calls.decrypt;
    const before = decrypts();
    assert.equal((await h.call("POST", `/locks/${body.vaultId}/unlock`)).status, 423);
    assert.equal(decrypts(), before, "no share was touched while locked");
    h.setTime(Date.parse(body.condition.unlockAt) + 3000);
    const res = await h.call("POST", `/locks/${body.vaultId}/unlock`);
    assert.equal(res.status, 200, JSON.stringify(res.json));
    assert.equal(res.json.dek, b64(dek));
  });

  it("one provider down: 503 naming the shares, then the guardian's share completes it", async () => {
    const { body, res: created, dek } = await create();
    h.setTime(Date.parse(body.condition.unlockAt) + 3000);
    secondInEnclave.down = true;
    try {
      let res = await h.call("POST", `/locks/${body.vaultId}/unlock`);
      assert.equal(res.status, 503);
      assert.equal(res.json.error, "insufficient-shares");
      assert.deepEqual(res.json.holders, { "escrow-kms": "ok", "second-provider": "unavailable", guardian: "not-provided" });

      // The guardian decrypts their share (equivalent to `age -d -i guardian.key share.age`).
      const share = await openGuardianShare(created.json.guardian.share, g.identity);
      res = await h.call("POST", `/locks/${body.vaultId}/unlock`, { guardianShare: b64(share) });
      assert.equal(res.status, 200, JSON.stringify(res.json));
      assert.equal(res.json.dek, b64(dek));
      const log = await h.call("GET", `/locks/${body.vaultId}/log`);
      const released = log.json.entries.find((e: { event: string }) => e.event === "released");
      assert.equal(released.detail.guardianShareUsed, true);
      assert.ok(!JSON.stringify(log.json).includes(b64(share)), "the share isn't logged");
    } finally {
      secondInEnclave.down = false;
    }
  });

  it("the guardian's share doesn't bypass the condition, and can't open a lock alone", async () => {
    const { body, res: created } = await create();
    const share = b64(await openGuardianShare(created.json.guardian.share, g.identity));
    assert.equal((await h.call("POST", `/locks/${body.vaultId}/unlock`, { guardianShare: share })).status, 423, "still locked");
    h.setTime(Date.parse(body.condition.unlockAt) + 3000);
    kmsInEnclave.down = true;
    secondInEnclave.down = true;
    try {
      const res = await h.call("POST", `/locks/${body.vaultId}/unlock`, { guardianShare: share });
      assert.equal(res.status, 503);
      assert.equal(res.json.holders.guardian, "ok");
    } finally {
      kmsInEnclave.down = secondInEnclave.down = false;
    }
    assert.equal((await h.call("POST", `/locks/${body.vaultId}/unlock`, { guardianShare: "!!" })).status, 400);
  });

  it("old single-key locks keep working next to split ones", async () => {
    const dek = newDek();
    const body = timeLockBody(h, { dek: b64(dek) });
    // A lock sealed before the split was turned on: a plain single-key wrap, inserted as it was stored.
    const single = await new MockKms({ service: kmsService }).wrap(dek, {
      vaultId: body.vaultId,
      seal: (await import("../src/conditions.js")).sealHash({ vaultId: body.vaultId, condition: body.condition as any, failsafeAt: body.failsafeAt }),
    });
    await h.db.query(
      `insert into locks (vault_id, condition_json, condition_sha256, wrapped_dek, status, unlock_at, failsafe_at, created_by_device, created_at)
       values ($1, $2::jsonb, $3, $4::jsonb, 'sealed', $5, $6, $7, $8)`,
      [body.vaultId, JSON.stringify(body.condition), "0".repeat(64), JSON.stringify(single), body.condition.unlockAt, body.failsafeAt, h.device.deviceId, h.clock.now],
    );
    h.setTime(Date.parse(body.condition.unlockAt) + 3000);
    const res = await h.call("POST", `/locks/${body.vaultId}/unlock`);
    assert.equal(res.status, 200, JSON.stringify(res.json));
    assert.equal(res.json.dek, b64(dek));
    assert.equal((await h.call("GET", `/locks/${body.vaultId}`)).json.guardian, null);
  });
});
