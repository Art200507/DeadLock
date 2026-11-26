import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { DecryptCommand, EncryptCommand } from "@aws-sdk/client-kms";
import { AwsKms, type KmsSender } from "../src/keywrap/aws-kms.js";
import { MockKms } from "../src/keywrap/mock-kms.js";
import {
  KeyAccessDeniedError,
  KeyServiceError,
  KeyWrapRegistry,
  UnwrapError,
  type KeyWrapper,
  type WrapContext,
  type WrappedKey,
} from "../src/keywrap/types.js";
import { randomBytes } from "node:crypto";
import { newDek, vaultId } from "./helpers.js";

const SEAL = "5e".repeat(32);
/** A random wrap context (vault ID + seal). */
const cx = () => ({ vaultId: vaultId(), seal: randomBytes(32).toString("hex") });

describe("MockKms (local stand-in for KMS)", () => {
  it("round-trips a key bound to its vault ID", async () => {
    const kms = new MockKms();
    const dek = newDek();
    const ctx = cx();
    const w = await kms.wrap(dek, ctx);
    assert.equal(w.scheme, "mock-kms/v1");
    assert.ok(!w.ciphertext.includes(Buffer.from(dek).toString("base64")));
    assert.deepEqual(await kms.unwrap(w, ctx), dek);
  });

  it("refuses another vault's context, tampering, and another master key", async () => {
    const kms = new MockKms();
    const ctx = cx();
    const w = await kms.wrap(newDek(), ctx);
    await assert.rejects(kms.unwrap(w, cx()), UnwrapError);
    await assert.rejects(kms.unwrap(w, { ...ctx, seal: "00".repeat(32) }), UnwrapError, "edited terms");
    const bytes = Buffer.from(w.ciphertext, "base64");
    bytes[20]! ^= 1;
    await assert.rejects(kms.unwrap({ ...w, ciphertext: bytes.toString("base64") }, ctx), UnwrapError);
    await assert.rejects(new MockKms({ keyId: w.keyId }).unwrap(w, ctx), UnwrapError);
    await assert.rejects(kms.wrap(newDek(), { vaultId: "not-hex", seal: SEAL }), TypeError);
    await assert.rejects(kms.wrap(newDek(), { vaultId: vaultId(), seal: "short" }), TypeError);
  });
});

/** A fake KMS that records commands and behaves like real KMS about encryption context. */
class FakeKms implements KmsSender {
  sent: (EncryptCommand | DecryptCommand)[] = [];
  failWith?: string;
  async send(cmd: EncryptCommand | DecryptCommand): Promise<unknown> {
    this.sent.push(cmd);
    if (this.failWith) {
      const e = new Error("simulated");
      e.name = this.failWith;
      throw e;
    }
    if (cmd instanceof EncryptCommand) {
      const blob = Buffer.from(JSON.stringify({ ctx: cmd.input.EncryptionContext, pt: Buffer.from(cmd.input.Plaintext!).toString("hex") }));
      return { CiphertextBlob: new Uint8Array(blob), KeyId: "arn:aws:kms:us-east-1:000000000000:key/fake" };
    }
    const { ctx, pt } = JSON.parse(Buffer.from(cmd.input.CiphertextBlob!).toString()) as { ctx: unknown; pt: string };
    if (JSON.stringify(ctx) !== JSON.stringify(cmd.input.EncryptionContext)) {
      const e = new Error("bad context");
      e.name = "InvalidCiphertextException";
      throw e;
    }
    return { Plaintext: new Uint8Array(Buffer.from(pt, "hex")) };
  }
}

describe("AwsKms adapter (fake KMS client, no AWS calls)", () => {
  it("encrypts with the configured key and the vault ID as encryption context", async () => {
    const fake = new FakeKms();
    const kms = new AwsKms({ keyId: "alias/condition-lock", client: fake });
    const v = vaultId();
    const dek = newDek();
    const w = await kms.wrap(dek, { vaultId: v, seal: SEAL });
    const enc = fake.sent[0] as EncryptCommand;
    assert.ok(enc instanceof EncryptCommand);
    assert.equal(enc.input.KeyId, "alias/condition-lock");
    assert.deepEqual(enc.input.EncryptionContext, { app: "condition-lock", vaultId: v, seal: SEAL });
    assert.equal(w.scheme, "aws-kms/v1");
    assert.equal(w.keyId, "arn:aws:kms:us-east-1:000000000000:key/fake");

    assert.deepEqual(await kms.unwrap(w, { vaultId: v, seal: SEAL }), dek);
    const dec = fake.sent[1] as DecryptCommand;
    assert.ok(dec instanceof DecryptCommand);
    assert.equal(dec.input.KeyId, w.keyId, "Decrypt is pinned to the key that wrapped it");
    assert.deepEqual(dec.input.EncryptionContext, { app: "condition-lock", vaultId: v, seal: SEAL });
    assert.equal(dec.input.Recipient, undefined, "no Recipient outside an enclave");
  });

  it("maps a context mismatch to UnwrapError and service failures to KeyServiceError", async () => {
    const fake = new FakeKms();
    const kms = new AwsKms({ keyId: "alias/condition-lock", client: fake });
    const w = await kms.wrap(newDek(), cx());
    await assert.rejects(kms.unwrap(w, cx()), UnwrapError);
    fake.failWith = "ThrottlingException";
    await assert.rejects(kms.unwrap(w, cx()), KeyServiceError);
    await assert.rejects(kms.wrap(newDek(), cx()), KeyServiceError);
    fake.failWith = "AccessDeniedException";
    await assert.rejects(kms.unwrap(w, cx()), KeyAccessDeniedError);
  });
});

describe("KeyWrapRegistry (the seam for future layers)", () => {
  /** A stand-in for a future layer (post-quantum, split-key...) built on the same interface. */
  class WrappingLayer implements KeyWrapper {
    readonly scheme = "test-layer/v1";
    constructor(private readonly inner: KeyWrapper) {}
    async wrap(pt: Uint8Array, ctx: WrapContext): Promise<WrappedKey> {
      const innerWrapped = await this.inner.wrap(pt, ctx);
      return { scheme: this.scheme, keyId: "layer", ciphertext: Buffer.from(JSON.stringify(innerWrapped)).toString("base64") };
    }
    async unwrap(w: WrappedKey, ctx: WrapContext): Promise<Uint8Array> {
      return this.inner.unwrap(JSON.parse(Buffer.from(w.ciphertext, "base64").toString()) as WrappedKey, ctx);
    }
  }

  it("wraps with the primary and unwraps any registered scheme", async () => {
    const mock = new MockKms();
    const layered = new WrappingLayer(mock);
    const before = new KeyWrapRegistry(mock);
    const ctx = cx();
    const dek = newDek();
    const old = await before.wrap(dek, ctx);

    // Switch the default to the new layer; old locks still unwrap.
    const after = new KeyWrapRegistry(layered, [mock]);
    const fresh = await after.wrap(dek, ctx);
    assert.equal(fresh.scheme, "test-layer/v1");
    assert.deepEqual(await after.unwrap(fresh, ctx), dek);
    assert.deepEqual(await after.unwrap(old, ctx), dek);
    assert.deepEqual(after.schemes, ["test-layer/v1", "mock-kms/v1"]);
  });

  it("refuses unknown schemes and duplicate registrations", async () => {
    const reg = new KeyWrapRegistry(new MockKms());
    await assert.rejects(reg.unwrap({ scheme: "nope/v1", keyId: "x", ciphertext: "" }, cx()), UnwrapError);
    assert.throws(() => new KeyWrapRegistry(new MockKms(), [new MockKms()]), /duplicate/);
  });
});
