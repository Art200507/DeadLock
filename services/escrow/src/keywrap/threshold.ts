/**
 * 2-of-3 key split. The vault's data key is split with Shamir's secret sharing
 * (`shamir-secret-sharing`, audited by Cure53 and Zellic) into three shares:
 *
 *   a. wrapped by the escrow's enclave-bound KMS key (holder "escrow-kms");
 *   b. wrapped by a second, independent provider behind the KeyWrapper interface ("second-provider");
 *   c. encrypted with age to a trusted person's public key ("guardian"), using the official
 *      TypeScript age implementation, so they can open it with the standard `age` tool.
 *
 * Any two shares rebuild the key; one alone reveals nothing. No single account (AWS, the second
 * provider, the guardian, or whoever runs the database) can release a key by itself. Unwrapping
 * happens in the key-release verifier, after the condition check: shares a and b are fetched
 * there (both providers' policies should require the enclave's attestation), and the guardian's
 * share, if needed, is passed in with the unlock request.
 *
 * Every share is bound to the vault and the seal: a and b through the providers' encryption
 * context, c through a header inside the age plaintext. A commitment (HMAC-SHA256 keyed by the
 * data key over vault ID + seal) detects a wrong or corrupted share, since Shamir itself can't.
 */
import { createHmac, timingSafeEqual } from "node:crypto";
import * as age from "age-encryption";
import { combine, split } from "shamir-secret-sharing";
import {
  KeyAccessDeniedError,
  KeyServiceError,
  UnwrapError,
  WrapInputError,
  contextFields,
  isWrappedKey,
  type KeyWrapper,
  type UnwrapOptions,
  type WrapContext,
  type WrapOptions,
  type WrappedKey,
} from "./types.js";

export const THRESHOLD_SCHEME = "shamir-2of3/v1";
const GUARDIAN_MAGIC = Buffer.from("CLG1");
const SHARE_LEN = 33; // 32-byte key + 1-byte x coordinate
export const GUARDIAN_SHARE_LEN = GUARDIAN_MAGIC.length + 16 + 32 + SHARE_LEN;

export type HolderName = "escrow-kms" | "second-provider" | "guardian";
export type HolderOutcome = "ok" | "denied" | "unavailable" | "refused" | "invalid" | "not-provided";

/** Fewer than two shares could be recovered. `holders` says what happened to each. */
export class InsufficientSharesError extends UnwrapError {
  override name = "InsufficientSharesError";
  constructor(readonly holders: Record<HolderName, HolderOutcome>) {
    super(`need 2 of 3 key shares; ${Object.entries(holders).map(([k, v]) => `${k}: ${v}`).join(", ")}`);
  }
}

export interface ThresholdParams {
  threshold: 2;
  commitment: string;
  shares: [
    { holder: "escrow-kms"; wrapped: WrappedKey },
    { holder: "second-provider"; wrapped: WrappedKey },
    { holder: "guardian"; recipient: string; age: string },
  ];
}

/** Validated vault ID and seal (contextFields throws on malformed input). */
function fields(ctx: WrapContext): { vaultId: string; seal: string } {
  contextFields(ctx);
  return { vaultId: ctx.vaultId, seal: ctx.seal };
}

function commitment(dek: Uint8Array, ctx: WrapContext): string {
  const f = fields(ctx);
  return createHmac("sha256", dek).update(`condlock/shamir-2of3/v1/commit\n${f.vaultId}\n${f.seal}`).digest("hex");
}

/** The guardian's plaintext: "CLG1" | vaultId (16) | seal (32) | share (33). */
export function encodeGuardianShare(share: Uint8Array, ctx: WrapContext): Uint8Array {
  const f = fields(ctx);
  return new Uint8Array(Buffer.concat([GUARDIAN_MAGIC, Buffer.from(f.vaultId, "hex"), Buffer.from(f.seal, "hex"), share]));
}

function decodeGuardianShare(blob: Uint8Array, ctx: WrapContext): Uint8Array | null {
  const f = fields(ctx);
  const b = Buffer.from(blob);
  if (b.length !== GUARDIAN_SHARE_LEN || !b.subarray(0, 4).equals(GUARDIAN_MAGIC)) return null;
  if (b.subarray(4, 20).toString("hex") !== f.vaultId || b.subarray(20, 52).toString("hex") !== f.seal) return null;
  return new Uint8Array(b.subarray(52));
}

/** What the guardian runs (or `age -d -i key.txt`): decrypt their armored share with their identity. */
export async function openGuardianShare(armored: string, identity: string): Promise<Uint8Array> {
  const d = new age.Decrypter();
  d.addIdentity(identity);
  return d.decrypt(age.armor.decode(armored));
}

export function parseThresholdParams(w: WrappedKey): ThresholdParams {
  const p = w.params as Partial<ThresholdParams> | undefined;
  const s = p?.shares;
  if (
    w.scheme !== THRESHOLD_SCHEME ||
    p?.threshold !== 2 ||
    typeof p.commitment !== "string" ||
    !/^[0-9a-f]{64}$/.test(p.commitment) ||
    !Array.isArray(s) ||
    s.length !== 3 ||
    s[0]?.holder !== "escrow-kms" ||
    !isWrappedKey(s[0].wrapped) ||
    s[1]?.holder !== "second-provider" ||
    !isWrappedKey(s[1].wrapped) ||
    s[2]?.holder !== "guardian" ||
    typeof s[2].recipient !== "string" ||
    typeof s[2].age !== "string"
  ) {
    throw new UnwrapError("malformed 2-of-3 wrapped key");
  }
  return p as ThresholdParams;
}

export class ThresholdKeyWrapper implements KeyWrapper {
  readonly scheme = THRESHOLD_SCHEME;

  constructor(
    private readonly holders: {
      /** Share a: the escrow's KMS key (in the enclave: attestation-bound). */
      escrowKms: KeyWrapper;
      /** Share b: an independent provider (another account, cloud or HSM). */
      secondProvider: KeyWrapper;
    },
  ) {}

  async wrap(dek: Uint8Array, ctx: WrapContext, options?: WrapOptions): Promise<WrappedKey> {
    const recipient = options?.guardianRecipient;
    if (!recipient) throw new WrapInputError("a 2-of-3 lock needs a guardian public key (an age recipient, age1...)");
    const enc = new age.Encrypter();
    try {
      enc.addRecipient(recipient);
    } catch {
      throw new WrapInputError("guardian recipient is not a valid age public key");
    }
    const shares = await split(dek, 3, 2);
    try {
      const guardianPlain = encodeGuardianShare(shares[2]!, ctx);
      const [wa, wb, ga] = await Promise.all([
        this.holders.escrowKms.wrap(shares[0]!, ctx),
        this.holders.secondProvider.wrap(shares[1]!, ctx),
        enc.encrypt(guardianPlain).finally(() => guardianPlain.fill(0)),
      ]);
      const params: ThresholdParams = {
        threshold: 2,
        commitment: commitment(dek, ctx),
        shares: [
          { holder: "escrow-kms", wrapped: wa },
          { holder: "second-provider", wrapped: wb },
          { holder: "guardian", recipient, age: age.armor.encode(ga) },
        ],
      };
      return { scheme: this.scheme, keyId: `${wa.keyId} + ${wb.keyId} + guardian`, ciphertext: "", params: params as unknown as Record<string, unknown> };
    } finally {
      for (const s of shares) s.fill(0);
    }
  }

  async unwrap(wrapped: WrappedKey, ctx: WrapContext, options?: UnwrapOptions): Promise<Uint8Array> {
    const p = parseThresholdParams(wrapped);
    const holders: Record<HolderName, HolderOutcome> = { "escrow-kms": "not-provided", "second-provider": "not-provided", guardian: "not-provided" };
    const got: Uint8Array[] = [];
    const outcome = (err: unknown): HolderOutcome =>
      err instanceof KeyAccessDeniedError ? "denied" : err instanceof UnwrapError ? "refused" : err instanceof KeyServiceError ? "unavailable" : "unavailable";

    const [ra, rb] = await Promise.allSettled([
      this.holders.escrowKms.unwrap(p.shares[0].wrapped, ctx),
      this.holders.secondProvider.unwrap(p.shares[1].wrapped, ctx),
    ]);
    for (const [name, r] of [["escrow-kms", ra], ["second-provider", rb]] as const) {
      if (r.status === "fulfilled" && r.value.length === SHARE_LEN) {
        holders[name] = "ok";
        got.push(r.value);
      } else {
        holders[name] = r.status === "fulfilled" ? "invalid" : outcome(r.reason);
      }
    }
    if (options?.guardianShare) {
      const g = decodeGuardianShare(options.guardianShare, ctx);
      if (g) {
        holders.guardian = "ok";
        got.push(g);
      } else {
        holders.guardian = "invalid";
      }
    }

    try {
      if (got.length < 2) throw new InsufficientSharesError(holders);
      // Try pairs until one rebuilds a key that matches the commitment.
      for (let i = 0; i < got.length; i++) {
        for (let j = i + 1; j < got.length; j++) {
          const dek = await combine([got[i]!, got[j]!]);
          if (dek.length === 32 && timingSafeEqual(Buffer.from(commitment(dek, ctx), "hex"), Buffer.from(p.commitment, "hex"))) return dek;
          dek.fill(0);
        }
      }
      throw new UnwrapError("the key shares don't rebuild this vault's key (a share is wrong or corrupted)");
    } finally {
      for (const s of got) s.fill(0);
    }
  }
}
