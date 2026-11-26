/**
 * End-to-end CLI test against the real drand quicknet. Skipped with CONDLOCK_OFFLINE=1.
 * Locks a mixed folder for one minute in a temp directory, checks it stays locked, then
 * polls `condlock unlock` until drand publishes the round.
 */
import assert from "node:assert/strict";
import * as fsp from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { after, describe, it } from "node:test";
import { QUICKNET, parseTlockEnvelope } from "@condlock/core";
import { EXIT, run } from "../../src/cli.js";
import { exists, hashTree, makeCtx, makeMixedFolder } from "../helpers/fixtures.js";

const skip = process.env.CONDLOCK_OFFLINE === "1" ? "CONDLOCK_OFFLINE=1" : false;

describe("condlock on real drand quicknet [network]", { skip }, () => {
  let work: string | undefined;
  after(async () => {
    if (work) await fsp.rm(work, { recursive: true, force: true });
  });

  it("locks a mixed folder for 1 minute, refuses early, then restores it", { timeout: 180_000 }, async () => {
    work = await fsp.mkdtemp(path.join(tmpdir(), "condlock-cli-net-"));
    const folder = await makeMixedFolder(path.join(work, "Holiday"), 8 * 1024 * 1024 + 5);
    const original = await hashTree(folder);
    const ctx = () => makeCtx({ cwd: work! });

    const lock = ctx();
    assert.equal(await run(["lock", "Holiday", "--until", "1m", "--yes"], lock), EXIT.OK, lock.text());
    assert.equal(await exists(folder), false, "originals deleted");
    const vault = `${folder}.condlock`;
    const env = parseTlockEnvelope(await fsp.readFile(path.join(vault, "keys", "timelock.json"), "utf8"));
    assert.equal(env.chain.hash, QUICKNET.hash);
    console.log(`# locked to drand round ${env.round}, unlocks at ${env.unlockAt}`);

    const early = ctx();
    assert.equal(await run(["unlock", vault], early), EXIT.STILL_LOCKED, early.text());
    assert.equal(early.lines[0], `still locked until ${env.unlockAt}`);
    console.log(`# before: ${early.lines[0]}`);

    let attempts = 0;
    for (;;) {
      attempts++;
      const c = ctx();
      const code = await run(["unlock", vault], c);
      if (code === EXIT.OK) {
        console.log(`# after: unlocked on attempt ${attempts}`);
        break;
      }
      assert.equal(code, EXIT.STILL_LOCKED, c.text());
      assert.ok(attempts < 50, "round never appeared");
      await sleep(QUICKNET.period * 1000);
    }
    assert.ok(attempts > 5, "it really stayed locked for a while");
    assert.deepEqual(await hashTree(folder), original, "restored byte for byte");
  });
});
