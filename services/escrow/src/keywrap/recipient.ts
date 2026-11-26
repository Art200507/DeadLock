/**
 * Attestation-bound decrypt ("Recipient") support, as used by AWS KMS with Nitro Enclaves.
 *
 * Inside the enclave, for each decrypt:
 *   1. generate an ephemeral RSA-2048 key pair;
 *   2. ask the Nitro Secure Module for an attestation document that embeds the public key
 *      (the document is signed by AWS and carries the image measurements, PCR0..PCR8);
 *   3. call KMS Decrypt with Recipient = { RSAES_OAEP_SHA_256, AttestationDocument };
 *   4. KMS checks the key policy (e.g. kms:RecipientAttestation:PCR0) and, instead of plaintext,
 *      returns CiphertextForRecipient: a CMS EnvelopedData (RFC 5652) whose content key is
 *      RSAES-OAEP-SHA256-encrypted to that public key and whose content is AES-256-CBC;
 *   5. open it with the ephemeral private key, which never leaves enclave memory.
 *
 * The parent instance relays the call but only ever sees the enveloped ciphertext.
 * ASN.1 parsing uses @peculiar/asn1-*; RSA and AES are Node's crypto. Nothing custom.
 *
 * Note: the CMS layout here follows AWS's documentation and SDKs and is exercised in tests by
 * the mock KMS, which builds the same structure; the real-KMS path is checked by the manual
 * enclave test in docs/ENCLAVE.md.
 */
import {
  ContentInfo,
  EncryptedContent,
  EncryptedContentInfo,
  EnvelopedData,
  KeyTransRecipientInfo,
  RecipientIdentifier,
  RecipientInfo,
  RecipientInfos,
  id_data,
  id_envelopedData,
} from "@peculiar/asn1-cms";
import { RsaEsOaepParams, id_RSAES_OAEP, id_mgf1, id_sha256 } from "@peculiar/asn1-rsa";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { AlgorithmIdentifier, SubjectKeyIdentifier } from "@peculiar/asn1-x509";
import {
  constants,
  createCipheriv,
  createDecipheriv,
  createHash,
  createPublicKey,
  generateKeyPairSync,
  privateDecrypt,
  publicEncrypt,
  randomBytes,
  type KeyObject,
} from "node:crypto";
import { UnwrapError } from "./types.js";

export const ID_AES256_CBC = "2.16.840.1.101.3.4.1.42";

/** Produces an attestation document embedding `publicKeyDer` (SPKI). In an enclave: the NSM. */
export interface AttestationProvider {
  readonly kind: string;
  attest(publicKeyDer: Uint8Array): Promise<Uint8Array>;
}

export interface RecipientKeyPair {
  /** SubjectPublicKeyInfo, DER: goes into the attestation document. */
  publicKeyDer: Uint8Array;
  privateKey: KeyObject;
}

export function newRecipientKeyPair(): RecipientKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return { publicKeyDer: new Uint8Array(publicKey.export({ type: "spki", format: "der" })), privateKey };
}

const sha256Alg = () => new AlgorithmIdentifier({ algorithm: id_sha256, parameters: null });

function oaepSha256Params(): ArrayBuffer {
  return AsnConvert.serialize(
    new RsaEsOaepParams({
      hashAlgorithm: sha256Alg(),
      maskGenAlgorithm: new AlgorithmIdentifier({ algorithm: id_mgf1, parameters: AsnConvert.serialize(sha256Alg()) }),
    }),
  );
}

/** Open a KMS CiphertextForRecipient with the enclave's ephemeral private key. */
export function openCiphertextForRecipient(cms: Uint8Array, privateKey: KeyObject): Uint8Array {
  const bad = (why: string): never => {
    throw new UnwrapError(`CiphertextForRecipient: ${why}`);
  };
  let env: EnvelopedData;
  try {
    const ci = AsnConvert.parse(cms, ContentInfo);
    if (ci.contentType !== id_envelopedData) bad("not CMS EnvelopedData");
    env = AsnConvert.parse(ci.content, EnvelopedData);
  } catch (err) {
    if (err instanceof UnwrapError) throw err;
    throw new UnwrapError("CiphertextForRecipient: malformed CMS", { cause: err });
  }

  const ktris = [...env.recipientInfos].map((r) => r.ktri).filter((k): k is KeyTransRecipientInfo => !!k);
  if (ktris.length !== 1) bad("expected exactly one key-transport recipient");
  const ktri = ktris[0]!;
  if (ktri.keyEncryptionAlgorithm.algorithm !== id_RSAES_OAEP) bad("key encryption is not RSAES-OAEP");
  if (!ktri.keyEncryptionAlgorithm.parameters) bad("RSAES-OAEP parameters missing (SHA-1 default not accepted)");
  const oaep = AsnConvert.parse(ktri.keyEncryptionAlgorithm.parameters!, RsaEsOaepParams);
  if (oaep.hashAlgorithm.algorithm !== id_sha256) bad("RSAES-OAEP hash is not SHA-256");
  if (oaep.maskGenAlgorithm.algorithm !== id_mgf1) bad("RSAES-OAEP mask is not MGF1");
  const mgfHash = AsnConvert.parse(oaep.maskGenAlgorithm.parameters!, AlgorithmIdentifier);
  if (mgfHash.algorithm !== id_sha256) bad("MGF1 hash is not SHA-256");

  const eci = env.encryptedContentInfo;
  if (eci.contentEncryptionAlgorithm.algorithm !== ID_AES256_CBC) bad("content encryption is not AES-256-CBC");
  const iv = new Uint8Array(AsnConvert.parse(eci.contentEncryptionAlgorithm.parameters!, OctetString).buffer);
  if (iv.length !== 16) bad("bad IV");
  const enc = eci.encryptedContent;
  const ct = enc?.value
    ? new Uint8Array(enc.value.buffer)
    : Buffer.concat((enc?.constructedValue ?? []).map((o) => new Uint8Array(o.buffer)));
  if (ct.length === 0 || ct.length % 16 !== 0) bad("bad encrypted content");

  let cek: Buffer | undefined;
  try {
    cek = privateDecrypt(
      { key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
      new Uint8Array(ktri.encryptedKey.buffer),
    );
    if (cek.length !== 32) bad("content key is not 256 bits");
    const d = createDecipheriv("aes-256-cbc", cek, iv);
    return new Uint8Array(Buffer.concat([d.update(ct), d.final()]));
  } catch (err) {
    if (err instanceof UnwrapError) throw err;
    throw new UnwrapError("CiphertextForRecipient: could not be opened with this enclave key", { cause: err });
  } finally {
    cek?.fill(0);
  }
}

/** Build a CiphertextForRecipient (what KMS does). Used by the mock KMS and by tests. */
export function sealForRecipient(plaintext: Uint8Array, publicKeyDer: Uint8Array): Uint8Array {
  const pub = createPublicKey({ key: Buffer.from(publicKeyDer), format: "der", type: "spki" });
  const cek = randomBytes(32);
  const iv = randomBytes(16);
  try {
    const c = createCipheriv("aes-256-cbc", cek, iv);
    const ct = Buffer.concat([c.update(plaintext), c.final()]);
    const encryptedKey = publicEncrypt({ key: pub, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, cek);
    const ski = createHash("sha1").update(publicKeyDer).digest();
    const env = new EnvelopedData({
      version: 2,
      recipientInfos: new RecipientInfos([
        new RecipientInfo({
          ktri: new KeyTransRecipientInfo({
            version: 2,
            rid: new RecipientIdentifier({ subjectKeyIdentifier: new SubjectKeyIdentifier(ski) }),
            keyEncryptionAlgorithm: new AlgorithmIdentifier({ algorithm: id_RSAES_OAEP, parameters: oaepSha256Params() }),
            encryptedKey: new OctetString(encryptedKey),
          }),
        }),
      ]),
      encryptedContentInfo: new EncryptedContentInfo({
        contentType: id_data,
        contentEncryptionAlgorithm: new AlgorithmIdentifier({
          algorithm: ID_AES256_CBC,
          parameters: AsnConvert.serialize(new OctetString(iv)),
        }),
        encryptedContent: new EncryptedContent({ value: new OctetString(ct) }),
      }),
    });
    return new Uint8Array(
      AsnConvert.serialize(new ContentInfo({ contentType: id_envelopedData, content: AsnConvert.serialize(env) })),
    );
  } finally {
    cek.fill(0);
  }
}

/**
 * Gets an attestation document by running a helper program (for real enclaves, a small NSM
 * client such as one built on aws-nitro-enclaves-nsm-api): the public key DER is written to its
 * stdin and the raw attestation document is read from its stdout.
 */
export class CommandAttestationProvider implements AttestationProvider {
  readonly kind = "command";
  constructor(
    private readonly command: string,
    private readonly args: string[] = [],
    private readonly timeoutMs = 10_000,
  ) {}

  async attest(publicKeyDer: Uint8Array): Promise<Uint8Array> {
    const { spawn } = await import("node:child_process");
    return new Promise((resolve, reject) => {
      const child = spawn(this.command, this.args, { stdio: ["pipe", "pipe", "pipe"] });
      const out: Buffer[] = [];
      const timer = setTimeout(() => child.kill("SIGKILL"), this.timeoutMs);
      child.stdout.on("data", (d: Buffer) => out.push(d));
      child.on("error", (e) => {
        clearTimeout(timer);
        reject(e);
      });
      child.on("close", (code) => {
        clearTimeout(timer);
        if (code !== 0) return reject(new Error(`attestation helper exited with ${code}`));
        const doc = Buffer.concat(out);
        if (doc.length === 0) return reject(new Error("attestation helper returned nothing"));
        resolve(new Uint8Array(doc));
      });
      child.stdin.end(Buffer.from(publicKeyDer));
    });
  }
}
