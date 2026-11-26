/**
 * The key-release verifier: the only component that ever asks KMS (or the second share holder)
 * to decrypt. In production it runs inside a Nitro Enclave with attestation-aware wrappers, so
 * the key policies let only this exact image (PCR0) decrypt. It keeps no state about locks and
 * reads no clock for decisions: time comes from BLS-verified drand beacons, game results from
 * its own TLS connections to two sports data providers.
 */
import { QUICKNET, roundForTime, timeOfRound, type DrandChain } from "@condlock/core";
import { fetchBeacon, type ChainClient, type ChainInfo } from "drand-client";
import { ConditionError, parseCondition, sealHash, type Condition } from "../conditions.js";
import { InsufficientSharesError, GUARDIAN_SHARE_LEN } from "../keywrap/threshold.js";
import {
  KeyAccessDeniedError,
  KeyServiceError,
  UnwrapError,
  isWrappedKey,
  type KeyWrapRegistry,
} from "../keywrap/types.js";
import type { NflChecker } from "../verifiers/nfl.js";
import { PROTOCOL_VERSION, type ReleaseRequest, type ReleaseResponse, type SecretsResponse } from "./protocol.js";
import type { SecretStore } from "./secrets.js";

export interface VerifierOptions {
  /** Unwrap side only. Inside the enclave: attestation-aware wrappers. */
  keys: KeyWrapRegistry;
  /** The drand chain whose beacons count as time evidence. Pinned to quicknet in production. */
  chain?: DrandChain;
  /** The NFL result verifier. Without it, NFL locks open only via the fail-safe. */
  nfl?: NflChecker;
  /** Where delivered credentials and API keys go. Without it, secrets messages are refused. */
  secrets?: SecretStore;
}

type Denial = Extract<ReleaseResponse, { ok: false }>;

function deny(code: Denial["code"], message: string, detail?: Record<string, unknown>): ReleaseResponse {
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
  private readonly nfl: NflChecker | undefined;
  private readonly secrets: SecretStore | undefined;

  constructor(opts: VerifierOptions) {
    this.keys = opts.keys;
    this.chain = opts.chain ?? QUICKNET;
    this.nfl = opts.nfl;
    this.secrets = opts.secrets;
  }

  /** Entry point for the channel: release requests and secrets deliveries. */
  async handle(input: unknown): Promise<ReleaseResponse | SecretsResponse> {
    const op = (input as { op?: unknown })?.op;
    if (op === "secrets") {
      if (!this.secrets) return { v: 1, ok: false, code: "bad-request", message: "this verifier takes no secrets" };
      return this.secrets.accept(input);
    }
    return this.release(input);
  }

  async release(input: unknown): Promise<ReleaseResponse> {
    // 1. Parse; trust nothing.
    const req = input as Partial<ReleaseRequest>;
    if (typeof req !== "object" || req === null || req.v !== PROTOCOL_VERSION || (req.op !== undefined && req.op !== "release")) {
      return deny("bad-request", "unsupported request");
    }
    if (typeof req.vaultId !== "string" || !/^[0-9a-f]{32}$/.test(req.vaultId)) return deny("bad-request", "vaultId");
    if (typeof req.failsafeAt !== "string" || Number.isNaN(Date.parse(req.failsafeAt))) return deny("bad-request", "failsafeAt");
    if (!isWrappedKey(req.wrappedDek)) return deny("bad-request", "wrappedDek");
    let guardianShare: Uint8Array | undefined;
    if (req.guardianShare !== undefined) {
      if (typeof req.guardianShare !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(req.guardianShare)) return deny("bad-request", "guardianShare");
      guardianShare = new Uint8Array(Buffer.from(req.guardianShare, "base64"));
      if (guardianShare.length !== GUARDIAN_SHARE_LEN) return deny("bad-request", "guardianShare has the wrong length");
    }
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
    const verifiedNow = timeOfRound(b.round, this.chain);

    // 3. Decide, from the sealed terms, drand and (for NFL) the verifier's own fetches.
    const failsafeRound = roundForTime(failsafeAt, this.chain);
    const failsafe = {
      latestRound: b.round,
      failsafeRound,
      failsafeAt: timeOfRound(failsafeRound, this.chain).toISOString(),
    };
    let via: "condition" | "failsafe" | null = null;
    let check: Record<string, unknown> = {};
    if (condition.type === "time") {
      const unlockRound = roundForTime(condition.unlockAt, this.chain);
      check = { unlockRound, unlockAt: timeOfRound(unlockRound, this.chain).toISOString() };
      via = b.round >= unlockRound ? "condition" : b.round >= failsafeRound ? "failsafe" : null;
    } else if (b.round >= failsafeRound) {
      via = "failsafe"; // no need to ask anyone about the game
    } else if (!this.nfl) {
      check = { reason: "this verifier has no NFL checker configured; only the fail-safe can open it" };
    } else {
      const verdict = await this.nfl.check(condition, verifiedNow);
      if (verdict.state === "unavailable") return deny("sources-unavailable", verdict.reason, failsafe);
      check = {
        reason: verdict.reason,
        ...(verdict.state === "not-met" ? { resolved: verdict.resolved } : {}),
        ...(verdict.state === "disagree" ? { disagree: true } : {}),
        reports: verdict.reports,
      };
      if (verdict.state === "met") via = "condition";
    }
    if (!via) return deny("still-locked", "still locked", { ...failsafe, ...check });

    // 4. Only now unwrap. The seal is bound into every share, so edited terms can't decrypt.
    let dek: Uint8Array;
    try {
      dek = await this.keys.unwrap(req.wrappedDek, { vaultId: req.vaultId, seal }, guardianShare ? { guardianShare } : undefined);
    } catch (err) {
      if (err instanceof InsufficientSharesError) {
        return deny("insufficient-shares", "fewer than 2 of the 3 key shares are available", { holders: err.holders, via, ...check });
      }
      if (err instanceof KeyAccessDeniedError) return deny("access-denied", "the key policy refused this verifier");
      if (err instanceof UnwrapError) return deny("unwrap-failed", "the key does not open for these terms");
      if (err instanceof KeyServiceError) return deny("key-service", "key service unavailable");
      return deny("key-service", "key service error");
    } finally {
      guardianShare?.fill(0);
    }
    try {
      return { v: PROTOCOL_VERSION, ok: true, via, dek: Buffer.from(dek).toString("base64"), ...(Object.keys(check).length ? { detail: check } : {}) };
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
