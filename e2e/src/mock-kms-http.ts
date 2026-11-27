/**
 * A local stand-in for the AWS KMS endpoint, speaking the real wire protocol (AWS JSON 1.1:
 * POST / with X-Amz-Target TrentService.Encrypt / TrentService.Decrypt), so the escrow's real
 * AwsKms adapter and the AWS SDK run unchanged on both sides. Each key is a MockKmsService with
 * the production policy shape: Encrypt for anyone, Decrypt only with a Recipient attestation
 * for the approved PCR0, signed by the (mock) Nitro root. Decrypt with a Recipient returns
 * CiphertextForRecipient (CMS), as KMS does.
 */
import type { IncomingMessage } from "node:http";
import { KeyAccessDeniedError, MockKmsService, UnwrapError } from "@condlock/escrow";

export interface KmsKey {
  arn: string;
  service: MockKmsService;
  /** Simulate an outage of this provider. */
  down: boolean;
}

export interface KmsCall {
  op: string;
  keyId: string;
  /** SigV4 access key ID from the Authorization header (proves the relayed credentials were used). */
  accessKeyId: string | null;
  recipient: boolean;
  outcome: string;
}

export class MockKmsHttp {
  readonly keys = new Map<string, KmsKey>();
  readonly calls: KmsCall[] = [];

  add(arn: string, service: MockKmsService): KmsKey {
    const k = { arn, service, down: false };
    this.keys.set(arn, k);
    return k;
  }

  async handle(req: IncomingMessage, body: string): Promise<{ status?: number; json: unknown; headers?: Record<string, string> }> {
    const headers = { "content-type": "application/x-amz-json-1.1" };
    const target = String(req.headers["x-amz-target"] ?? "");
    const op = target.replace(/^TrentService\./, "");
    const accessKeyId = /Credential=([^/]+)\//.exec(String(req.headers.authorization ?? ""))?.[1] ?? null;
    const input = (body ? JSON.parse(body) : {}) as {
      KeyId?: string;
      Plaintext?: string;
      CiphertextBlob?: string;
      EncryptionContext?: Record<string, string>;
      Recipient?: { AttestationDocument?: string };
    };
    const key = this.keys.get(input.KeyId ?? "");
    const call: KmsCall = { op, keyId: input.KeyId ?? "", accessKeyId, recipient: Boolean(input.Recipient), outcome: "?" };
    this.calls.push(call);
    const fail = (status: number, type: string, message: string) => {
      call.outcome = type;
      return { status, headers, json: { __type: type, message } };
    };
    if (!key) return fail(400, "NotFoundException", `key ${input.KeyId} does not exist`);
    if (key.down) return fail(500, "KMSInternalException", "the key service is unavailable");
    const ec = input.EncryptionContext ?? {};
    if (ec.app !== "condition-lock" || !ec.vaultId || !ec.seal) return fail(400, "AccessDeniedException", "encryption context required by policy");
    const ctx = { vaultId: ec.vaultId, seal: ec.seal };
    try {
      if (op === "Encrypt") {
        const ct = await key.service.encrypt(new Uint8Array(Buffer.from(input.Plaintext ?? "", "base64")), ctx);
        call.outcome = "ok";
        return { headers, json: { CiphertextBlob: ct, KeyId: key.arn, EncryptionAlgorithm: "SYMMETRIC_DEFAULT" } };
      }
      if (op === "Decrypt") {
        const doc = input.Recipient?.AttestationDocument;
        const out = await key.service.decrypt(
          input.CiphertextBlob ?? "",
          ctx,
          doc ? { attestationDocument: new Uint8Array(Buffer.from(doc, "base64")) } : undefined,
        );
        call.outcome = "ok";
        return {
          headers,
          json: {
            KeyId: key.arn,
            EncryptionAlgorithm: "SYMMETRIC_DEFAULT",
            ...(out.ciphertextForRecipient ? { CiphertextForRecipient: Buffer.from(out.ciphertextForRecipient).toString("base64") } : {}),
            ...(out.plaintext ? { Plaintext: Buffer.from(out.plaintext).toString("base64") } : {}),
          },
        };
      }
      return fail(400, "UnsupportedOperationException", op);
    } catch (err) {
      if (err instanceof KeyAccessDeniedError) return fail(400, "AccessDeniedException", err.message);
      if (err instanceof UnwrapError) return fail(400, "InvalidCiphertextException", err.message);
      throw err;
    }
  }
}
