/**
 * Network tests against the real drand quicknet. Skipped when CONDLOCK_OFFLINE=1
 * (`pnpm test:offline`). The lock target comes from drand's latest round, and
 * waiting is done by polling drand; the laptop clock plays no part.
 */
import assert from "node:assert/strict";
import { setTimeout as sleep } from "node:timers/promises";
import { describe, it } from "node:test";
import {
  QUICKNET,
  StillLockedError,
  createDrandClient,
  generateDek,
  generateId,
  toHex,
  unwrapDek,
  wrapDek,
} from "../../src/index.js";

const skip = process.env.CONDLOCK_OFFLINE === "1" ? "CONDLOCK_OFFLINE=1" : false;
const ONE_MINUTE_OF_ROUNDS = 60 / QUICKNET.period; // 20 rounds

describe("tlock on real drand quicknet [network]", { skip }, () => {
  it("opens a key locked to a past round immediately", async () => {
    const dek = generateDek();
    const env = await wrapDek({ dek, vaultId: toHex(generateId()), target: { round: 1_000 } });
    assert.deepEqual(await unwrapDek(env), dek);
  });

  it("a 1-minute lock is still locked first, then opens", { timeout: 180_000 }, async () => {
    const client = createDrandClient();
    const latest = await client.latest();
    const round = latest.round + ONE_MINUTE_OF_ROUNDS;
    const dek = generateDek();
    const env = await wrapDek({ dek, vaultId: toHex(generateId()), target: { round } });
    console.log(`# locked to round ${round} (latest ${latest.round}), unlocks at ${env.unlockAt}`);

    await assert.rejects(unwrapDek(env, { client }), (err: unknown) => {
      assert.ok(err instanceof StillLockedError, `expected StillLockedError, got ${String(err)}`);
      assert.match(err.message, new RegExp(`^still locked until ${env.unlockAt.replace(/\./g, "\\.")}`));
      console.log(`# before: ${err.message}`);
      return true;
    });

    let attempts = 0;
    for (;;) {
      attempts++;
      try {
        const opened = await unwrapDek(env, { client });
        assert.deepEqual(opened, dek);
        console.log(`# after: opened on attempt ${attempts}`);
        break;
      } catch (err) {
        if (!(err instanceof StillLockedError)) throw err;
        assert.ok(attempts < 50, "round never appeared");
        await sleep(QUICKNET.period * 1000);
      }
    }
    assert.ok(attempts > 5, "it really was locked for a while");
  });
});
