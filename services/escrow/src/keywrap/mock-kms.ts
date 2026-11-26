/**
 * Local stand-ins for AWS KMS and the Nitro Secure Module, for tests and local development only.
 *
 * MockKmsService behaves like one KMS key: AES-256-GCM under a master key held in this process's
 * memory, the encryption context as associated data, and an optional key policy that only allows
 * Decrypt with a Recipient attestation whose PCR0 matches (like kms:RecipientAttestation:PCR0).
 * With a Recipient it returns CiphertextForRecipient (CMS) instead of plaintext, exactly as KMS
 * does, so the enclave-side code path is the real one.
 *
 * MockNsm issues attestation documents for a given PCR0, signed by a mock root key that the mock
 * KMS trusts (standing in for the AWS Nitro root of trust). The document format is our own JSON,
 * not AWS's CBOR/COSE: only the KMS side ever parses it.
 *
 * Restarting the process loses the master key and every key wrapped with it, by design.
 */
import { generateKeyPairSync, randomBytes, sign, verify, webcrypto, type KeyObject } from "node:crypto";
import {
  type AttestationProvider,
  newRecipientKeyPair,
  openCiphertextForRecipient,
  sealForRecipient,
} from "./recipient.js";
import {
  KeyAccessDeniedError,
  UnwrapError,
  canonicalContext,
  type KeyWrapper,
  type WrapContext,
  type WrappedKey,
} from "./types.js";

const subtle = webcrypto.subtle;
const NONCE = 12;

export interface MockKeyPolicy {
  /** If set, Decrypt is allowed only with a valid Recipient attestation for this PCR0 (hex). */
  requireAttestedPcr0?: string;
}

interface MockAttestationDoc {
  format: "mock-nitro-attestation/v1";
  moduleId: string;
  pcrs: Record<string, string>;
  publicKey: string; // base64 SPKI DER
  timestamp: number;
}

export class MockKmsService {
  readonly keyId: string;
  private readonly key: Promise<webcrypto.CryptoKey>;
  calls = { encrypt: 0, decrypt: 0, denied: 0 };

  constructor(
    private readonly opts: { keyId?: string; masterKey?: Uint8Array; policy?: MockKeyPolicy; attestationRoot?: KeyObject } = {},
  ) {
    this.keyId = opts.keyId ?? `mock:${randomBytes(8).toString("hex")}`;
    const raw = opts.masterKey ?? new Uint8Array(randomBytes(32));
    if (raw.length !== 32) throw new TypeError("mock master key must be 32 bytes");
    this.key = subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
    if (opts.policy?.requireAttestedPcr0 && !opts.attestationRoot) {
      throw new Error("an attestation policy needs a trusted attestation root");
    }
  }

  async encrypt(plaintext: Uint8Array, context: WrapContext): Promise<string> {
    this.calls.encrypt++;
    const aad = new TextEncoder().encode(canonicalContext(context));
    const nonce = webcrypto.getRandomValues(new Uint8Array(NONCE));
    const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, await this.key, plaintext));
    return Buffer.concat([nonce, ct]).toString("base64");
  }

  async decrypt(
    ciphertext: string,
    context: WrapContext,
    recipient?: { attestationDocument: Uint8Array },
  ): Promise<{ plaintext?: Uint8Array; ciphertextForRecipient?: Uint8Array }> {
    this.calls.decrypt++;
    let recipientKey: Uint8Array | undefined;
    if (recipient) recipientKey = this.checkAttestation(recipient.attestationDocument);
    if (this.opts.policy?.requireAttestedPcr0 && !recipientKey) {
      this.calls.denied++;
      throw new KeyAccessDeniedError("AccessDeniedException: key policy requires an enclave attestation");
    }
    const aad = new TextEncoder().encode(canonicalContext(context));
    const blob = Buffer.from(ciphertext, "base64");
    let pt: Uint8Array;
    try {
      pt = new Uint8Array(
        await subtle.decrypt({ name: "AES-GCM", iv: blob.subarray(0, NONCE), additionalData: aad }, await this.key, blob.subarray(NONCE)),
      );
    } catch {
      throw new UnwrapError("InvalidCiphertextException: does not open under this context (tampered or moved)");
    }
    if (!recipientKey) return { plaintext: pt };
    try {
      return { ciphertextForRecipient: sealForRecipient(pt, recipientKey) };
    } finally {
      pt.fill(0);
    }
  }

  /** Verify the document's signature and PCR0; return the recipient public key. */
  private checkAttestation(docBytes: Uint8Array): Uint8Array {
    const deny = (why: string): never => {
      this.calls.denied++;
      throw new KeyAccessDeniedError(`AccessDeniedException: ${why}`);
    };
    if (!this.opts.attestationRoot) return deny("no trusted attestation root");
    let parsed: { doc: MockAttestationDoc; signature: string };
    try {
      parsed = JSON.parse(Buffer.from(docBytes).toString("utf8"));
    } catch {
      return deny("malformed attestation document");
    }
    const body = Buffer.from(JSON.stringify(parsed.doc));
    if (!verify(null, body, this.opts.attestationRoot, Buffer.from(parsed.signature ?? "", "base64"))) {
      return deny("attestation signature invalid");
    }
    const want = this.opts.policy?.requireAttestedPcr0;
    if (want && parsed.doc.pcrs["0"]?.toLowerCase() !== want.toLowerCase()) return deny("PCR0 does not match the key policy");
    return new Uint8Array(Buffer.from(parsed.doc.publicKey, "base64"));
  }
}

/** A mock Nitro Secure Module: attests to a fixed PCR0 with a mock root key. */
export class MockNsm implements AttestationProvider {
  readonly kind = "mock-nsm";
  constructor(
    private readonly pcr0: string,
    private readonly rootPrivateKey: KeyObject,
  ) {}

  /** A root of trust (stand-in for the AWS Nitro root CA): KMS trusts `publicKey`, NSMs sign with `privateKey`. */
  static newRoot(): { publicKey: KeyObject; privateKey: KeyObject } {
    return generateKeyPairSync("ed25519");
  }

  async attest(publicKeyDer: Uint8Array): Promise<Uint8Array> {
    const doc: MockAttestationDoc = {
      format: "mock-nitro-attestation/v1",
      moduleId: "mock-enclave",
      pcrs: { "0": this.pcr0 },
      publicKey: Buffer.from(publicKeyDer).toString("base64"),
      timestamp: Date.now(),
    };
    const signature = sign(null, Buffer.from(JSON.stringify(doc)), this.rootPrivateKey).toString("base64");
    return new Uint8Array(Buffer.from(JSON.stringify({ doc, signature })));
  }
}

/** KeyWrapper over a MockKmsService; with `attestation` it decrypts the enclave way (Recipient). */
export class MockKms implements KeyWrapper {
  readonly scheme = "mock-kms/v1";
  readonly service: MockKmsService;
  private readonly attestation: AttestationProvider | undefined;

  constructor(opts: { service?: MockKmsService; attestation?: AttestationProvider; keyId?: string; masterKey?: Uint8Array } = {}) {
    this.service =
      opts.service ??
      new MockKmsService({ ...(opts.keyId ? { keyId: opts.keyId } : {}), ...(opts.masterKey ? { masterKey: opts.masterKey } : {}) });
    this.attestation = opts.attestation;
  }

  get keyId(): string {
    return this.service.keyId;
  }

  async wrap(plaintext: Uint8Array, context: WrapContext): Promise<WrappedKey> {
    return { scheme: this.scheme, keyId: this.service.keyId, ciphertext: await this.service.encrypt(plaintext, context) };
  }

  async unwrap(wrapped: WrappedKey, context: WrapContext): Promise<Uint8Array> {
    if (wrapped.scheme !== this.scheme || wrapped.keyId !== this.service.keyId) {
      throw new UnwrapError("wrapped key was made by a different key");
    }
    if (!this.attestation) {
      const { plaintext } = await this.service.decrypt(wrapped.ciphertext, context);
      return plaintext!;
    }
    const { publicKeyDer, privateKey } = newRecipientKeyPair();
    const doc = await this.attestation.attest(publicKeyDer);
    const { ciphertextForRecipient } = await this.service.decrypt(wrapped.ciphertext, context, { attestationDocument: doc });
    if (!ciphertextForRecipient) throw new UnwrapError("expected CiphertextForRecipient");
    return openCiphertextForRecipient(ciphertextForRecipient, privateKey);
  }
}
