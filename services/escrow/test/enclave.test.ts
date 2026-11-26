/**
 * Enclave-readiness, with mocked attestation: the key policy only lets an attested verifier
 * image (PCR0) decrypt; the verifier distrusts everything the API host sends; the narrow release
 * interface works in-process and over a real Unix socket.
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import * as fsp from "node:fs/promises";
import * as net from "node:net";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { after, before, describe, it } from "node:test";
import { DecryptCommand, EncryptCommand } from "@aws-sdk/client-kms";
import { sealHash, parseCondition } from "../src/conditions.js";
import { AwsKms, type KmsSender } from "../src/keywrap/aws-kms.js";
import { MockKms, MockKmsService, MockNsm } from "../src/keywrap/mock-kms.js";
import {
  CommandAttestationProvider,
  newRecipientKeyPair,
  openCiphertextForRecipient,
  sealForRecipient,
} from "../src/keywrap/recipient.js";
import { KeyAccessDeniedError, KeyWrapRegistry, UnwrapError } from "../src/keywrap/types.js";
import type { ReleaseRequest } from "../src/verifier/protocol.js";
import { SocketReleaser, serveVerifier } from "../src/verifier/transport.js";
import { KeyReleaseVerifier } from "../src/verifier/verifier.js";
import { ENCLAVE_PCR0, MockDrand, b64, harness, newDek, timeLockBody, vaultId, type Harness } from "./helpers.js";

describe("CiphertextForRecipient (CMS EnvelopedData, RSAES-OAEP-SHA256 + AES-256-CBC)", () => {
  it("round-trips to the enclave's ephemeral key", () => {
    const kp = newRecipientKeyPair();
    const dek = newDek();
    const cms = sealForRecipient(dek, kp.publicKeyDer);
    assert.equal(cms[0], 0x30, "DER SEQUENCE");
    assert.deepEqual(openCiphertextForRecipient(cms, kp.privateKey), dek);
  });

  it("can't be opened with another key, and rejects tampering or junk", () => {
    const kp = newRecipientKeyPair();
    const cms = sealForRecipient(newDek(), kp.publicKeyDer);
    assert.throws(() => openCiphertextForRecipient(cms, newRecipientKeyPair().privateKey), UnwrapError);
    const tampered = cms.slice();
    tampered[tampered.length - 5]! ^= 1;
    assert.throws(() => openCiphertextForRecipient(tampered, kp.privateKey), UnwrapError);
    assert.throws(() => openCiphertextForRecipient(new Uint8Array([1, 2, 3]), kp.privateKey), UnwrapError);
  });
});

describe("attestation-bound decrypt (mock KMS key policy on PCR0)", () => {
  const root = MockNsm.newRoot();
  const service = new MockKmsService({ policy: { requireAttestedPcr0: ENCLAVE_PCR0 }, attestationRoot: root.publicKey });
  const ctx = { vaultId: vaultId(), seal: randomBytes(32).toString("hex") };

  it("the attested enclave image decrypts; plaintext never comes back in the clear", async () => {
    const parent = new MockKms({ service });
    const enclave = new MockKms({ service, attestation: new MockNsm(ENCLAVE_PCR0, root.privateKey) });
    const dek = newDek();
    const wrapped = await parent.wrap(dek, ctx);
    assert.deepEqual(await enclave.unwrap(wrapped, ctx), dek);
    const raw = await service.decrypt(wrapped.ciphertext, ctx, { attestationDocument: await new MockNsm(ENCLAVE_PCR0, root.privateKey).attest(newRecipientKeyPair().publicKeyDer) });
    assert.equal(raw.plaintext, undefined, "KMS returns only CiphertextForRecipient");
    assert.ok(raw.ciphertextForRecipient);
  });

  it("the parent host, a different image, or a forged attestation can't decrypt", async () => {
    const parent = new MockKms({ service });
    const wrapped = await parent.wrap(newDek(), ctx);
    await assert.rejects(parent.unwrap(wrapped, ctx), KeyAccessDeniedError, "no attestation");
    const otherImage = new MockKms({ service, attestation: new MockNsm("cd".repeat(48), root.privateKey) });
    await assert.rejects(otherImage.unwrap(wrapped, ctx), KeyAccessDeniedError, "wrong PCR0");
    const forger = new MockKms({ service, attestation: new MockNsm(ENCLAVE_PCR0, MockNsm.newRoot().privateKey) });
    await assert.rejects(forger.unwrap(wrapped, ctx), KeyAccessDeniedError, "not signed by the trusted root");
  });

  it("even the attested enclave can't decrypt under edited terms", async () => {
    const enclave = new MockKms({ service, attestation: new MockNsm(ENCLAVE_PCR0, root.privateKey) });
    const wrapped = await new MockKms({ service }).wrap(newDek(), ctx);
    await assert.rejects(enclave.unwrap(wrapped, { ...ctx, seal: "00".repeat(32) }), UnwrapError);
  });
});

describe("AwsKms with attestation (fake KMS that honours Recipient)", () => {
  const root = MockNsm.newRoot();

  class RecipientFakeKms implements KmsSender {
    sent: (EncryptCommand | DecryptCommand)[] = [];
    leakPlaintext = false;
    async send(cmd: EncryptCommand | DecryptCommand): Promise<unknown> {
      this.sent.push(cmd);
      if (cmd instanceof EncryptCommand) {
        return { CiphertextBlob: new Uint8Array(Buffer.from(Buffer.from(cmd.input.Plaintext!).toString("hex"))), KeyId: "arn:fake" };
      }
      const pt = new Uint8Array(Buffer.from(Buffer.from(cmd.input.CiphertextBlob!).toString(), "hex"));
      const att = cmd.input.Recipient?.AttestationDocument;
      if (!att) {
        const e = new Error("no attestation");
        e.name = "AccessDeniedException";
        throw e;
      }
      const { doc } = JSON.parse(Buffer.from(att).toString()) as { doc: { publicKey: string } };
      const cfr = sealForRecipient(pt, new Uint8Array(Buffer.from(doc.publicKey, "base64")));
      return this.leakPlaintext ? { CiphertextForRecipient: cfr, Plaintext: pt } : { CiphertextForRecipient: cfr };
    }
  }

  it("sends a Recipient with RSAES_OAEP_SHA_256 and the attestation document, and opens the CMS reply", async () => {
    const fake = new RecipientFakeKms();
    const nsm = new MockNsm(ENCLAVE_PCR0, root.privateKey);
    const kms = new AwsKms({ keyId: "alias/condition-lock", client: fake, attestation: nsm });
    const ctx = { vaultId: vaultId(), seal: randomBytes(32).toString("hex") };
    const dek = newDek();
    const w = await kms.wrap(dek, ctx);
    assert.deepEqual(await kms.unwrap(w, ctx), dek);
    const dec = fake.sent[1] as DecryptCommand;
    assert.equal(dec.input.Recipient?.KeyEncryptionAlgorithm, "RSAES_OAEP_SHA_256");
    assert.ok(dec.input.Recipient?.AttestationDocument?.length);
    assert.deepEqual(dec.input.EncryptionContext, { app: "condition-lock", vaultId: ctx.vaultId, seal: ctx.seal });
  });

  it("refuses a reply that carries plaintext despite a Recipient", async () => {
    const fake = new RecipientFakeKms();
    fake.leakPlaintext = true;
    const kms = new AwsKms({ keyId: "k", client: fake, attestation: new MockNsm(ENCLAVE_PCR0, root.privateKey) });
    const ctx = { vaultId: vaultId(), seal: randomBytes(32).toString("hex") };
    await assert.rejects(kms.unwrap(await kms.wrap(newDek(), ctx), ctx), /plaintext despite a Recipient/);
  });

  it("gets attestation documents from a helper command (stdin: public key, stdout: document)", async () => {
    const echo = new CommandAttestationProvider(process.execPath, ["-e", "process.stdin.pipe(process.stdout)"]);
    const der = newRecipientKeyPair().publicKeyDer;
    assert.deepEqual(await echo.attest(der), der);
    await assert.rejects(new CommandAttestationProvider(process.execPath, ["-e", "process.exit(3)"]).attest(der), /exited with 3/);
  });
});

describe("the verifier trusts nothing the API host sends", () => {
  const drand = new MockDrand();
  const service = new MockKmsService();
  const kms = new MockKms({ service });
  const verifier = new KeyReleaseVerifier({ keys: new KeyWrapRegistry(kms), chain: drand.chainParams });
  const roundOf = (iso: string) => Math.ceil((Date.parse(iso) - drand.info.genesis_time * 1000) / 3000) + 1;

  async function sealed(unlockAt: string, failsafeAt: string) {
    const v = vaultId();
    const condition = parseCondition({ type: "time", unlockAt });
    const dek = newDek();
    const wrappedDek = await kms.wrap(dek, { vaultId: v, seal: sealHash({ vaultId: v, condition, failsafeAt }) });
    const req = (round: number, overrides: Partial<ReleaseRequest> = {}): ReleaseRequest => ({
      v: 1,
      vaultId: v,
      condition,
      failsafeAt,
      wrappedDek,
      evidence: { drandBeacon: drand.beacon(round) as { round: number; signature: string; randomness: string } },
      ...overrides,
    });
    return { v, dek, req, unlockRound: roundOf(unlockAt) };
  }

  it("releases only with a valid beacon at or after the unlock round", async () => {
    const s = await sealed("2027-01-01T00:00:00.000Z", "2028-01-01T00:00:00.000Z");
    const early = await verifier.release(s.req(s.unlockRound - 1));
    assert.equal(early.ok, false);
    assert.equal(!early.ok && early.code, "still-locked");
    const on = await verifier.release(s.req(s.unlockRound));
    assert.ok(on.ok && on.via === "condition" && on.dek === b64(s.dek));
  });

  it("rejects a forged or mismatched beacon", async () => {
    const s = await sealed("2027-01-01T00:00:00.000Z", "2028-01-01T00:00:00.000Z");
    const good = drand.beacon(s.unlockRound) as { round: number; signature: string; randomness: string };
    const forged = { ...good, round: s.unlockRound + 1000 };
    for (const beacon of [forged, { ...good, signature: "00".repeat(48) }, new MockDrand().beacon(s.unlockRound + 5)]) {
      const r = await verifier.release(s.req(0, { evidence: { drandBeacon: beacon as typeof good } }));
      assert.equal(!r.ok && r.code, "bad-evidence");
    }
    const none = await verifier.release(s.req(0, { evidence: {} }));
    assert.equal(!none.ok && none.code, "bad-evidence");
  });

  it("an edited condition or fail-safe doesn't decrypt, even with valid evidence", async () => {
    const s = await sealed("2030-01-01T00:00:00.000Z", "2031-01-01T00:00:00.000Z");
    const now = roundOf("2027-01-01T00:00:00.000Z");
    const editedCondition = await verifier.release(
      s.req(now, { condition: parseCondition({ type: "time", unlockAt: "2026-01-01T00:00:00.000Z" }) }),
    );
    assert.equal(!editedCondition.ok && editedCondition.code, "unwrap-failed");
    const editedFailsafe = await verifier.release(s.req(now, { failsafeAt: "2026-06-01T00:00:00.000Z" }));
    assert.equal(!editedFailsafe.ok && editedFailsafe.code, "unwrap-failed");
    const otherVault = await verifier.release(s.req(roundOf("2030-01-02T00:00:00.000Z"), { vaultId: vaultId() }));
    assert.equal(!otherVault.ok && otherVault.code, "unwrap-failed");
  });

  it("rejects malformed requests", async () => {
    for (const bad of [null, {}, { v: 2 }, { v: 1, vaultId: "x" }]) {
      const r = await verifier.release(bad);
      assert.equal(!r.ok && r.code, "bad-request");
    }
  });
});

describe("full flow with the mocked enclave", () => {
  let h: Harness;
  before(async () => (h = await harness({ enclave: true, socket: true })));
  after(() => h.close());

  it("locks and releases through the attested verifier over a Unix socket", async () => {
    const dek = newDek();
    const body = timeLockBody(h, { dek: b64(dek) });
    assert.equal((await h.call("POST", "/locks", body)).status, 201);
    assert.equal((await h.call("POST", `/locks/${body.vaultId}/unlock`)).status, 423);
    h.setTime(Date.parse(body.condition.unlockAt) + 3000);
    const res = await h.call("POST", `/locks/${body.vaultId}/unlock`);
    assert.equal(res.status, 200, JSON.stringify(res.json));
    assert.equal(res.json.dek, b64(dek));
    assert.ok(h.service!.calls.decrypt >= 1);
  });

  it("the API host's own KMS access can't decrypt stored keys", async () => {
    const body = timeLockBody(h);
    await h.call("POST", "/locks", body);
    const { rows } = await h.db.query<{ wrapped_dek: never }>("select wrapped_dek from locks where vault_id = $1", [body.vaultId]);
    const seal = sealHash({ vaultId: body.vaultId, condition: parseCondition(body.condition), failsafeAt: body.failsafeAt });
    await assert.rejects(h.kms.unwrap(rows[0]!.wrapped_dek, { vaultId: body.vaultId, seal }), KeyAccessDeniedError);
  });
});

describe("a verifier built from a different image is refused by the key policy", () => {
  let h: Harness;
  before(async () => (h = await harness({ enclave: { verifierPcr0: "ee".repeat(48) } })));
  after(() => h.close());

  it("returns 500 and audits access-denied", async () => {
    const body = timeLockBody(h);
    await h.call("POST", "/locks", body);
    h.setTime(Date.parse(body.condition.unlockAt) + 3000);
    const res = await h.call("POST", `/locks/${body.vaultId}/unlock`);
    assert.equal(res.status, 500);
    const { rows } = await h.db.query<{ detail_json: { reason: string } }>(
      "select detail_json from audit_log where vault_id = $1 and event = 'unlock-failed'",
      [body.vaultId],
    );
    assert.equal(rows[0]!.detail_json.reason, "access-denied");
    assert.equal((await h.call("GET", `/locks/${body.vaultId}`)).json.status, "sealed");
  });
});

describe("socket transport", () => {
  let dir: string;
  before(async () => (dir = await fsp.mkdtemp(path.join(tmpdir(), "condlock-sock-"))));
  after(() => fsp.rm(dir, { recursive: true, force: true }));

  it("drops oversized or non-JSON frames without answering", async () => {
    const verifier = new KeyReleaseVerifier({ keys: new KeyWrapRegistry(new MockKms()) });
    const p = path.join(dir, "v.sock");
    const server = await serveVerifier(verifier, { path: p });
    try {
      const send = (bytes: Buffer) =>
        new Promise<string>((resolve) => {
          const s = net.createConnection(p, () => s.write(bytes));
          let got = "";
          s.on("data", (d) => (got += d.toString()));
          s.on("close", () => resolve(got));
        });
      const huge = Buffer.alloc(4);
      huge.writeUInt32BE(10 * 1024 * 1024);
      assert.equal(await send(huge), "");
      const junk = Buffer.from("garbage!");
      const len = Buffer.alloc(4);
      len.writeUInt32BE(junk.length);
      assert.equal(await send(Buffer.concat([len, junk])), "");
      // A well-formed but bad request gets a proper denial.
      const r = await new SocketReleaser({ path: p }).release({ v: 1 } as unknown as ReleaseRequest);
      assert.equal(!r.ok && r.code, "bad-request");
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });

  it("fails cleanly when the verifier isn't there", async () => {
    await assert.rejects(new SocketReleaser({ path: path.join(dir, "missing.sock") }).release({} as ReleaseRequest));
  });
});
