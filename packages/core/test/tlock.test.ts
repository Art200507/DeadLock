import assert from "node:assert/strict";
import { afterEach, describe, it, mock } from "node:test";
import { roundTime as drandRoundTime } from "drand-client";
import { defaultChainInfo } from "tlock-js";
import { decodeArmor, encodeArmor } from "tlock-js/age/armor.js";
import {
  DrandUnavailableError,
  IntegrityError,
  QUICKNET,
  StillLockedError,
  createDrandClient,
  generateDek,
  generateId,
  parseTlockEnvelope,
  roundForTime,
  serializeTlockEnvelope,
  timeOfRound,
  toHex,
  unwrapDek,
  wrapDek,
  type TlockEnvelope,
} from "../src/index.js";
import { MockDrand } from "./helpers/mock-drand.js";

afterEach(() => mock.restoreAll());

const vaultId = () => toHex(generateId());

/** Wrap a fresh DEK on a mock network to `round`. */
async function setup(round = 100) {
  const drand = new MockDrand();
  const dek = generateDek();
  const id = vaultId();
  const env = await wrapDek({ dek, vaultId: id, target: { round }, chain: drand.chainParams });
  return { drand, dek, id, env };
}

describe("round-for-time math", () => {
  const g = QUICKNET.genesisTime * 1000;

  it("pins the same quicknet parameters tlock-js ships", () => {
    assert.equal(QUICKNET.hash, defaultChainInfo.hash);
    assert.equal(QUICKNET.publicKey, defaultChainInfo.public_key);
    assert.equal(QUICKNET.period, defaultChainInfo.period);
    assert.equal(QUICKNET.genesisTime, defaultChainInfo.genesis_time);
    assert.equal(QUICKNET.schemeID, defaultChainInfo.schemeID);
    assert.equal(QUICKNET.beaconID, "quicknet");
  });

  it("maps boundaries exactly and always rounds up", () => {
    assert.equal(roundForTime(g), 1);
    assert.equal(roundForTime(g + 1), 2);
    assert.equal(roundForTime(g + 2999), 2);
    assert.equal(roundForTime(g + 3000), 2);
    assert.equal(roundForTime(g + 3001), 3);
    assert.equal(roundForTime(g + 6000), 3);
  });

  it("matches a known quicknet date", () => {
    // 2027-01-01T09:00:00Z is exactly (1798794000 - 1692803367) / 3 = 35330211 periods after genesis.
    assert.equal(roundForTime("2027-01-01T09:00:00Z"), 35_330_212);
    assert.equal(roundForTime("2027-01-01T09:00:00.001Z"), 35_330_213);
    assert.equal(timeOfRound(35_330_212).toISOString(), "2027-01-01T09:00:00.000Z");
  });

  it("never picks a round that publishes before the target (10k random times)", () => {
    const info = { ...defaultChainInfo };
    for (let i = 0; i < 10_000; i++) {
      const t = g + Math.floor(Math.random() * 20 * 365 * 86_400_000);
      const r = roundForTime(t);
      assert.ok(timeOfRound(r).getTime() >= t, "round publishes at or after target");
      if (r > 1) assert.ok(timeOfRound(r - 1).getTime() < t, "it is the earliest such round");
      assert.equal(timeOfRound(r).getTime(), drandRoundTime(info, r), "agrees with drand-client");
    }
  });

  it("accepts Date, ISO string and epoch ms; rejects junk and pre-genesis times", () => {
    const d = new Date("2030-06-01T12:00:00Z");
    assert.equal(roundForTime(d), roundForTime(d.toISOString()));
    assert.equal(roundForTime(d), roundForTime(d.getTime()));
    assert.throws(() => roundForTime("not a date"), RangeError);
    assert.throws(() => roundForTime(g - 1), RangeError);
    assert.throws(() => timeOfRound(0), RangeError);
    assert.throws(() => timeOfRound(1.5), RangeError);
  });

  it("uses a different period and genesis when given another chain", () => {
    const chain = { ...QUICKNET, genesisTime: 1000, period: 30 };
    assert.equal(roundForTime(1_000_000, chain), 1);
    assert.equal(roundForTime(1_030_000, chain), 2);
    assert.equal(roundForTime(1_030_001, chain), 3);
  });
});

describe("tlock wrap/unwrap (offline, mocked drand)", () => {
  it("wraps without any network access and stores round + chain info", async () => {
    const fetchMock = mock.method(globalThis, "fetch", async () => {
      throw new Error("network used during wrap");
    });
    const dek = generateDek();
    const id = vaultId();
    const env = await wrapDek({ dek, vaultId: id, target: { unlockAt: "2027-01-01T09:00:00Z" } });
    assert.equal(fetchMock.mock.callCount(), 0);
    assert.equal(env.round, 35_330_212);
    assert.equal(env.unlockAt, "2027-01-01T09:00:00.000Z");
    assert.deepEqual(env.chain, { ...QUICKNET });
    assert.equal(env.vaultId, id);
    assert.match(env.ciphertext, /^-----BEGIN AGE ENCRYPTED FILE-----/);
    assert.ok(!env.ciphertext.includes(Buffer.from(dek).toString("base64")));
    assert.deepEqual(parseTlockEnvelope(serializeTlockEnvelope(env)), env);
  });

  it("is still locked before the round is published, and opens after", async () => {
    const { drand, dek, env } = await setup(100);
    drand.publish(99);
    await assert.rejects(unwrapDek(env, { client: drand }), (err: unknown) => {
      assert.ok(err instanceof StillLockedError);
      assert.equal(err.round, 100);
      assert.equal(err.latestRound, 99);
      assert.equal(err.message.split(" (")[0], `still locked until ${env.unlockAt}`);
      return true;
    });
    drand.publish(100);
    assert.deepEqual(await unwrapDek(env, { client: drand }), dek);
    drand.publish(5000);
    assert.deepEqual(await unwrapDek(env, { client: drand }), dek, "still opens long after");
  });

  it("ignores the laptop clock entirely", async () => {
    const { drand, dek, env } = await setup(100);
    drand.publish(50);
    // Clock set 100 years ahead: still locked, because drand hasn't published the round.
    const farFuture = Date.now() + 100 * 365 * 86_400_000;
    const nowMock = mock.method(Date, "now", () => farFuture);
    await assert.rejects(unwrapDek(env, { client: drand }), StillLockedError);
    // Clock set to 1970: opens anyway once the round exists.
    nowMock.mock.mockImplementation(() => 0);
    drand.publish(100);
    assert.deepEqual(await unwrapDek(env, { client: drand }), dek);
    assert.equal(nowMock.mock.callCount(), 0, "Date.now() was never consulted");
  });

  it("fails when the envelope's round is edited", async () => {
    const { drand, env } = await setup(100);
    drand.publish(200);
    for (const round of [99, 101, 1]) {
      const forged: TlockEnvelope = { ...env, round, unlockAt: timeOfRound(round, env.chain).toISOString() };
      await assert.rejects(unwrapDek(forged, { client: drand }), IntegrityError, `round ${round}`);
    }
    // Editing the round without fixing unlockAt is caught by validation.
    await assert.rejects(unwrapDek({ ...env, round: 50 }, { client: drand }), IntegrityError);
  });

  it("fails when the round inside the ciphertext is rewritten to an earlier one", async () => {
    const { drand, env } = await setup(100);
    drand.publish(60); // the attacker's target round is already out
    const plain = decodeArmor(env.ciphertext);
    assert.ok(plain.includes(`-> tlock 100 ${env.chain.hash}`));
    const forged: TlockEnvelope = {
      ...env,
      round: 60,
      unlockAt: timeOfRound(60, env.chain).toISOString(),
      ciphertext: encodeArmor(plain.replace(`-> tlock 100 `, `-> tlock 60 `)),
    };
    await assert.rejects(unwrapDek(forged, { client: drand }), IntegrityError);
  });

  it("fails on tampered ciphertext", async () => {
    const { drand, env } = await setup(100);
    drand.publish(100);
    const lines = env.ciphertext.trimEnd().split("\n");
    const bodyLines = lines.slice(1, -1);
    for (let li = 0; li < bodyLines.length; li++) {
      for (const pos of [0, Math.floor(bodyLines[li]!.length / 2), bodyLines[li]!.length - 3]) {
        const line = bodyLines[li]!;
        const ch = line[pos]!;
        if (ch === "=") continue;
        const swapped = line.slice(0, pos) + (ch === "A" ? "B" : "A") + line.slice(pos + 1);
        const tampered = [lines[0], ...bodyLines.map((l, i) => (i === li ? swapped : l)), lines.at(-1)].join("\n") + "\n";
        await assert.rejects(
          unwrapDek({ ...env, ciphertext: tampered }, { client: drand }),
          IntegrityError,
          `line ${li} pos ${pos}`,
        );
      }
    }
  });

  it("fails when an envelope is moved to another vault", async () => {
    const { drand, env } = await setup(100);
    drand.publish(100);
    await assert.rejects(unwrapDek({ ...env, vaultId: vaultId() }, { client: drand }), /different vault/);
  });

  it("fails against a different drand chain", async () => {
    const { env } = await setup(100);
    const other = new MockDrand();
    other.publish(100);
    await assert.rejects(unwrapDek(env, { client: other }), /different chain/);
    // Pointing the envelope at the other chain doesn't help: its key can't open this ciphertext.
    const repointed = { ...env, chain: other.chainParams };
    await assert.rejects(unwrapDek(repointed, { client: other }), IntegrityError);
  });

  it("rejects a beacon for the wrong round from a lying relay", async () => {
    const { drand, env } = await setup(100);
    drand.publish(101);
    drand.serveWrongRound = true;
    await assert.rejects(unwrapDek(env, { client: drand }), DrandUnavailableError);
  });

  it("reports drand being unreachable as unknown, not as locked or unlocked", async () => {
    const { drand, env } = await setup(100);
    drand.publish(100);
    drand.offline = true;
    await assert.rejects(unwrapDek(env, { client: drand }), DrandUnavailableError);
  });

  it("refuses a client with beacon verification turned off", async () => {
    const { drand, env } = await setup(100);
    drand.publish(100);
    drand.options = { ...drand.options, disableBeaconVerification: true };
    await assert.rejects(unwrapDek(env, { client: drand }), /verification disabled/);
  });

  it("validates inputs", async () => {
    await assert.rejects(wrapDek({ dek: new Uint8Array(16), vaultId: vaultId(), target: { round: 5 } }), TypeError);
    await assert.rejects(wrapDek({ dek: generateDek(), vaultId: "xyz", target: { round: 5 } }));
    await assert.rejects(wrapDek({ dek: generateDek(), vaultId: vaultId(), target: { round: 0 } }), RangeError);
    assert.throws(() => parseTlockEnvelope("{"), IntegrityError);
    assert.throws(() => parseTlockEnvelope({ format: "nope" }), IntegrityError);
  });

  it("builds a pinned, verifying HTTP client for quicknet", () => {
    const c = createDrandClient();
    assert.equal(c.options.disableBeaconVerification, false);
    assert.equal(c.chain().baseUrl, `https://api.drand.sh/${QUICKNET.hash}`);
  });
});
