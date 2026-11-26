/**
 * The narrow interface between the API (untrusted parent host) and the key-release verifier
 * (designed to run inside a Nitro Enclave). One request, one response, plain JSON, so it can go
 * over vsock in production, a Unix socket locally, or an in-process call in tests.
 *
 * The verifier trusts nothing in the request: it recomputes the seal from the terms, checks
 * time with a BLS-verified drand beacon, and only then asks KMS to decrypt, with an encryption
 * context that includes the seal. If the API lies about the condition, the fail-safe or the
 * vault, KMS refuses; if it lies about time, the beacon check refuses.
 */
import type { Condition } from "../conditions.js";
import type { WrappedKey } from "../keywrap/types.js";

export const PROTOCOL_VERSION = 1;
export const MAX_FRAME_BYTES = 64 * 1024;

export interface DrandBeaconEvidence {
  round: number;
  signature: string;
  randomness: string;
}

export interface ReleaseRequest {
  v: 1;
  vaultId: string;
  condition: Condition;
  failsafeAt: string;
  wrappedDek: WrappedKey;
  evidence: {
    /** Any verified quicknet beacon proves "now is at least this round's time". */
    drandBeacon?: DrandBeaconEvidence;
  };
}

export type ReleaseDenialCode = "still-locked" | "bad-request" | "bad-evidence" | "unwrap-failed" | "access-denied" | "key-service";

export type ReleaseResponse =
  | { v: 1; ok: true; via: "condition" | "failsafe"; dek: string }
  | { v: 1; ok: false; code: ReleaseDenialCode; message: string; detail?: Record<string, unknown> };

/** What the API talks to. Implementations: in-process (tests/dev), socket (vsock via bridge). */
export interface KeyReleaser {
  release(req: ReleaseRequest): Promise<ReleaseResponse>;
}
