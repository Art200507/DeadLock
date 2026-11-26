/**
 * The one manual test against real AWS KMS. Not part of `pnpm test`; run it yourself:
 *
 *   cp services/escrow/.env.example services/escrow/.env   # set CONDLOCK_REAL_KMS_KEY_ID, AWS_REGION, AWS_PROFILE
 *   pnpm --filter @condlock/escrow test:real-kms
 *
 * Use a throwaway TEST key whose policy lets your own principal Encrypt and Decrypt (no enclave):
 * see services/escrow/README.md. It makes about 6 KMS requests (inside the free tier) and creates
 * nothing. The enclave-locked production key can't be used here, by design.
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { after, before, describe, it } from "node:test";
import { sealHash, parseCondition } from "../../src/conditions.js";
import { AwsKms } from "../../src/keywrap/aws-kms.js";
import { UnwrapError } from "../../src/keywrap/types.js";
import { b64, harness, newDek, timeLockBody, vaultId, type Harness } from "../helpers.js";

const keyId = process.env.CONDLOCK_REAL_KMS_KEY_ID;
const skip = keyId ? false : "set CONDLOCK_REAL_KMS_KEY_ID (see services/escrow/README.md)";

describe("real AWS KMS [manual]", { skip }, () => {
  const kms = () => new AwsKms({ keyId: keyId!, ...(process.env.AWS_REGION ? { region: process.env.AWS_REGION } : {}) });

  it("wraps and unwraps with vault ID + seal as encryption context, and refuses other contexts", async () => {
    const k = kms();
    const ctx = { vaultId: vaultId(), seal: randomBytes(32).toString("hex") };
    const dek = newDek();
    const w = await k.wrap(dek, ctx);
    assert.equal(w.scheme, "aws-kms/v1");
    assert.match(w.keyId, /^arn:aws:kms:/);
    assert.deepEqual(await k.unwrap(w, ctx), dek);
    await assert.rejects(k.unwrap(w, { ...ctx, vaultId: vaultId() }), UnwrapError, "other vault");
    await assert.rejects(k.unwrap(w, { ...ctx, seal: "00".repeat(32) }), UnwrapError, "edited terms");
  });

  describe("full API flow with real KMS and in-memory Postgres", () => {
    let h: Harness;
    before(async () => (h = await harness({ kms: kms() })));
    after(() => h?.close());

    it("seals a lock and releases it once drand reaches the unlock round", async () => {
      const dek = newDek();
      const body = timeLockBody(h, { dek: b64(dek) });
      const created = await h.call("POST", "/locks", body);
      assert.equal(created.status, 201, JSON.stringify(created.json));
      const seal = sealHash({ vaultId: body.vaultId, condition: parseCondition(body.condition), failsafeAt: body.failsafeAt });
      assert.equal(seal.length, 64);
      h.setTime(Date.parse(body.condition.unlockAt) + 3000);
      const res = await h.call("POST", `/locks/${body.vaultId}/unlock`);
      assert.equal(res.status, 200, JSON.stringify(res.json));
      assert.equal(res.json.dek, b64(dek));
    });
  });
});
