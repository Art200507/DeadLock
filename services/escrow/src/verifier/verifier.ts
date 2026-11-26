/**
 * The key-release verifier: the only component that ever asks KMS to decrypt. In production it
 * runs inside a Nitro Enclave with an attestation-aware KMS wrapper, so the key policy lets only
 * this exact image (PCR0) decrypt. It keeps no state and reads no clock.
 */
import { QUICKNET, roundForTime, timeOfRound, type DrandChain } from "@condlock/core";
import { fetchBeacon, type ChainClient, type ChainInfo } from "drand-client";
import { ConditionError, parseCondition, sealHash, type Condition } from "../conditions.js";
import {
  KeyAccessDeniedError,
  KeyServiceError,
  UnwrapError,
  isWrappedKey,
  type KeyWrapRegistry,
} from "../keywrap/types.js";
import { PROTOCOL_VERSION, type ReleaseRequest, type ReleaseResponse } from "./protocol.js";

export interface VerifierOptions {
  /** Unwrap side only. Inside the enclave: an AwsKms with an attestation provider. */
  keys: KeyWrapRegistry;
  /** The drand chain whose beacons count as time evidence. Pinned to quicknet in production. */
  chain?: DrandChain;
}

function deny(code: Extract<ReleaseResponse, { ok: false }>["code"], message: string, detail?: Record<string, unknown>): ReleaseResponse {
  return { v: PROTOCOL_VERSION, ok: false, code, message, ...(detail ? { detail } : {}) };
}

function chainInfo(c: DrandChain): ChainInfo {
  return {
    hash: c.hash,
    public_key: c.publicKey,
    period: c.period,
    genesis_time: c.genesisTime,
    schemeID: c.schemeID,
    groupHash: c.groupHash,
    metadata: { beaconID: c.beaconID },
  };
}

export class KeyReleaseVerifier {
  private readonly keys: KeyWrapRegistry;
  private readonly chain: DrandChain;

  constructor(opts: VerifierOptions) {
    this.keys = opts.keys;
    this.chain = opts.chain ?? QUICKNET;
  }

  async release(input: unknown): Promise<ReleaseResponse> {
    // 1. Parse; trust nothing.
    const req = input as Partial<ReleaseRequest>;
    if (typeof req !== "object" || req === null || req.v !== PROTOCOL_VERSION) return deny("bad-request", "unsupported request");
    if (typeof req.vaultId !== "string" || !/^[0-9a-f]{32}$/.test(req.vaultId)) return deny("bad-request", "vaultId");
    if (typeof req.failsafeAt !== "string" || Number.isNaN(Date.parse(req.failsafeAt))) return deny("bad-request", "failsafeAt");
    if (!isWrappedKey(req.wrappedDek)) return deny("bad-request", "wrappedDek");
    let condition: Condition;
    try {
      condition = parseCondition(req.condition);
    } catch (err) {
      return deny("bad-request", err instanceof ConditionError ? err.message : "condition");
    }
    const failsafeAt = new Date(req.failsafeAt);
    const seal = sealHash({ vaultId: req.vaultId, condition, failsafeAt });

    // 2. Time evidence: a drand beacon whose BLS signature verifies against the pinned chain.
    const b = req.evidence?.drandBeacon;
    if (!b || !Number.isSafeInteger(b.round) || b.round < 1 || typeof b.signature !== "string" || typeof b.randomness !== "string") {
      return deny("bad-evidence", "a drand beacon is required");
    }
    if (!(await this.beaconIsValid(b))) return deny("bad-evidence", "drand beacon failed verification");

    // 3. Decide, from the sealed terms and drand alone.
    const failsafeRound = roundForTime(failsafeAt, this.chain);
    const unlockRound = condition.type === "time" ? roundForTime(condition.unlockAt, this.chain) : null;
    const via =
      unlockRound !== null && b.round >= unlockRound ? "condition" : b.round >= failsafeRound ? "failsafe" : null;
    if (!via) {
      return deny("still-locked", "still locked", {
        latestRound: b.round,
        failsafeRound,
        failsafeAt: timeOfRound(failsafeRound, this.chain).toISOString(),
        ...(unlockRound !== null
          ? { unlockRound, unlockAt: timeOfRound(unlockRound, this.chain).toISOString() }
          : { waitingFor: `${condition.type} verifier (milestone 5)` }),
      });
    }

    // 4. Only now ask KMS. The seal in the context means edited terms can't decrypt.
    let dek: Uint8Array;
    try {
      dek = await this.keys.unwrap(req.wrappedDek, { vaultId: req.vaultId, seal });
    } catch (err) {
      if (err instanceof KeyAccessDeniedError) return deny("access-denied", "the key policy refused this verifier");
      if (err instanceof UnwrapError) return deny("unwrap-failed", "the key does not open for these terms");
      if (err instanceof KeyServiceError) return deny("key-service", "key service unavailable");
      return deny("key-service", "key service error");
    }
    try {
      return { v: PROTOCOL_VERSION, ok: true, via, dek: Buffer.from(dek).toString("base64") };
    } finally {
      dek.fill(0);
    }
  }

  private async beaconIsValid(b: { round: number; signature: string; randomness: string }): Promise<boolean> {
    const info = chainInfo(this.chain);
    const beacon = { round: b.round, signature: b.signature, randomness: b.randomness };
    // Reuse drand-client's verification by serving the evidence through a stub client.
    const client: ChainClient = {
      options: { disableBeaconVerification: false, noCache: false },
      chain: () => ({ baseUrl: "evidence:", info: async () => info }),
      get: async () => beacon,
      latest: async () => beacon,
    };
    try {
      await fetchBeacon(client, b.round);
      return true;
    } catch {
      return false;
    }
  }
}
