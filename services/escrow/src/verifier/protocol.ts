/**
 * The narrow interface between the API (untrusted parent host) and the key-release verifier
 * (designed to run inside a Nitro Enclave). One request, one response, plain JSON, so it can go
 * over vsock in production, a Unix socket locally, or an in-process call in tests.
 *
 * The verifier trusts nothing in the request: it recomputes the seal from the terms, checks
 * time with a BLS-verified drand beacon, and only then asks KMS to decrypt, with an encryption
 * context that includes the seal. If the API lies about the condition, the fail-safe or the
 * vault, KMS refuses; if it lies about time, the beacon check refuses. NFL results are fetched
 * by the verifier itself over TLS (src/egress), never taken from the request.
 *
 * Two message kinds share the channel: release requests (no `op`, or op "release") and
 * `op: "secrets"`, which the parent uses to deliver short-lived AWS credentials and the sports
 * API keys into the enclave (it has no instance metadata service of its own).
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
  op?: "release";
  vaultId: string;
  condition: Condition;
  failsafeAt: string;
  wrappedDek: WrappedKey;
  evidence: {
    /** Any verified quicknet beacon proves "now is at least this round's time". */
    drandBeacon?: DrandBeaconEvidence;
  };
  /** 2-of-3 locks: the guardian's decrypted share (base64), when another holder is unavailable. */
  guardianShare?: string;
}

export interface AwsCredentialsMessage {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  /** ISO time; the verifier stops using the credentials after it. */
  expiration?: string;
}

/** Parent → verifier: what the enclave can't fetch for itself. Replaces what was there before. */
export interface SecretsMessage {
  v: 1;
  op: "secrets";
  aws?: AwsCredentialsMessage;
  sports?: { apiSportsKey?: string; theSportsDbKey?: string };
}

export type SecretsResponse = { v: 1; ok: true; op: "secrets"; stored: string[] } | { v: 1; ok: false; code: "bad-request"; message: string };

export type ReleaseDenialCode =
  | "still-locked"
  | "bad-request"
  | "bad-evidence"
  | "unwrap-failed"
  | "access-denied"
  | "key-service"
  /** NFL: a result source couldn't be reached; try again later. */
  | "sources-unavailable"
  /** 2-of-3: fewer than two shares could be recovered (detail.holders says why). */
  | "insufficient-shares";

export type ReleaseResponse =
  | { v: 1; ok: true; via: "condition" | "failsafe"; dek: string; detail?: Record<string, unknown> }
  | { v: 1; ok: false; code: ReleaseDenialCode; message: string; detail?: Record<string, unknown> };

/** What the API talks to. Implementations: in-process (tests/dev), socket (vsock via bridge). */
export interface KeyReleaser {
  release(req: ReleaseRequest): Promise<ReleaseResponse>;
}
