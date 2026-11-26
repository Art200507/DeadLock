/**
 * AWS KMS envelope wrapping. One symmetric customer-managed key wraps every vault's DEK with
 * EncryptionContext { app: "condition-lock", vaultId, seal }, so a wrapped key can't be decrypted
 * for another vault or under edited terms, and a key policy can require that context.
 *
 * With `attestation` set (inside a Nitro Enclave), Decrypt sends a Recipient with a fresh
 * attestation document; KMS returns CiphertextForRecipient, opened with the enclave's ephemeral
 * key. A key policy conditioned on kms:RecipientAttestation:PCR0 then makes the key decryptable
 * only from that enclave image (see docs/ENCLAVE.md).
 */
import { DecryptCommand, EncryptCommand, KMSClient, type KMSClientConfig } from "@aws-sdk/client-kms";
import { newRecipientKeyPair, openCiphertextForRecipient, type AttestationProvider } from "./recipient.js";
import {
  KeyAccessDeniedError,
  KeyServiceError,
  UnwrapError,
  contextFields,
  type KeyWrapper,
  type WrapContext,
  type WrappedKey,
} from "./types.js";

/** The one method we need from KMSClient; tests pass a fake. */
export interface KmsSender {
  send(command: EncryptCommand | DecryptCommand): Promise<unknown>;
}

export interface AwsKmsOptions {
  /** Key ID, ARN or alias ("alias/condition-lock"). */
  keyId: string;
  region?: string;
  /** Override the KMS endpoint, e.g. the enclave's local bridge to the parent's vsock-proxy. */
  endpoint?: string;
  client?: KmsSender;
  /** Inside an enclave: attest and decrypt via Recipient so the parent never sees plaintext. */
  attestation?: AttestationProvider;
  /** Inside an enclave: the credentials the parent delivered (SecretStore.awsCredentials). */
  credentials?: KMSClientConfig["credentials"];
  /** Inside an enclave: a NodeHttpHandler on the egress agent, so TLS to KMS ends in the enclave. */
  requestHandler?: KMSClientConfig["requestHandler"];
}

const CIPHERTEXT_ERRORS = new Set(["InvalidCiphertextException", "IncorrectKeyException"]);

export class AwsKms implements KeyWrapper {
  readonly scheme = "aws-kms/v1";
  private readonly keyId: string;
  private readonly client: KmsSender;
  private readonly attestation: AttestationProvider | undefined;

  constructor(opts: AwsKmsOptions) {
    if (!opts.keyId) throw new Error("AWS KMS key ID is required");
    this.keyId = opts.keyId;
    this.attestation = opts.attestation;
    this.client =
      opts.client ??
      new KMSClient({
        ...(opts.region ? { region: opts.region } : {}),
        ...(opts.endpoint ? { endpoint: opts.endpoint } : {}),
        ...(opts.credentials ? { credentials: opts.credentials } : {}),
        ...(opts.requestHandler ? { requestHandler: opts.requestHandler } : {}),
      });
  }

  async wrap(plaintext: Uint8Array, context: WrapContext): Promise<WrappedKey> {
    let out: { CiphertextBlob?: Uint8Array; KeyId?: string };
    try {
      out = (await this.client.send(
        new EncryptCommand({
          KeyId: this.keyId,
          Plaintext: plaintext,
          EncryptionContext: contextFields(context),
          EncryptionAlgorithm: "SYMMETRIC_DEFAULT",
        }),
      )) as typeof out;
    } catch (err) {
      throw new KeyServiceError(`KMS Encrypt failed: ${(err as Error).name}`, { cause: err });
    }
    if (!out.CiphertextBlob) throw new KeyServiceError("KMS Encrypt returned no ciphertext");
    return {
      scheme: this.scheme,
      keyId: out.KeyId ?? this.keyId,
      ciphertext: Buffer.from(out.CiphertextBlob).toString("base64"),
    };
  }

  async unwrap(wrapped: WrappedKey, context: WrapContext): Promise<Uint8Array> {
    if (wrapped.scheme !== this.scheme) throw new UnwrapError(`not an ${this.scheme} key`);
    const recipient = this.attestation ? newRecipientKeyPair() : undefined;
    let attestationDocument: Uint8Array | undefined;
    if (recipient) {
      try {
        attestationDocument = await this.attestation!.attest(recipient.publicKeyDer);
      } catch (err) {
        throw new KeyServiceError("could not get an attestation document", { cause: err });
      }
    }
    let out: { Plaintext?: Uint8Array; CiphertextForRecipient?: Uint8Array };
    try {
      out = (await this.client.send(
        new DecryptCommand({
          KeyId: wrapped.keyId,
          CiphertextBlob: Buffer.from(wrapped.ciphertext, "base64"),
          EncryptionContext: contextFields(context),
          EncryptionAlgorithm: "SYMMETRIC_DEFAULT",
          ...(attestationDocument
            ? { Recipient: { KeyEncryptionAlgorithm: "RSAES_OAEP_SHA_256", AttestationDocument: attestationDocument } }
            : {}),
        }),
      )) as typeof out;
    } catch (err) {
      const name = (err as Error).name;
      if (CIPHERTEXT_ERRORS.has(name)) {
        throw new UnwrapError(`KMS refused to decrypt (${name}): wrong vault, terms, key or tampered ciphertext`, { cause: err });
      }
      if (name === "AccessDeniedException") {
        throw new KeyAccessDeniedError("KMS denied Decrypt (key policy: attestation or caller not allowed)", { cause: err });
      }
      throw new KeyServiceError(`KMS Decrypt failed: ${name}`, { cause: err });
    }
    if (recipient) {
      // With a Recipient, KMS must not return plaintext; refuse it if it does.
      if (out.Plaintext && out.Plaintext.length) throw new UnwrapError("KMS returned plaintext despite a Recipient");
      if (!out.CiphertextForRecipient) throw new KeyServiceError("KMS Decrypt returned no CiphertextForRecipient");
      return openCiphertextForRecipient(new Uint8Array(out.CiphertextForRecipient), recipient.privateKey);
    }
    if (!out.Plaintext) throw new KeyServiceError("KMS Decrypt returned no plaintext");
    return new Uint8Array(out.Plaintext);
  }
}
