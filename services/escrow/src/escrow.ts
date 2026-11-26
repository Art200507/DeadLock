/**
 * The escrow service (the API side). It seals locks and wraps their keys (KMS Encrypt only), keeps
 * the database and the audit log, and enforces "released once". It never decrypts: releasing a
 * key is the verifier's job (src/verifier), which in production runs in a Nitro Enclave and is
 * the only thing the KMS key policy lets decrypt. There is no "release" button and no way to edit
 * or delete a condition.
 */
import { randomBytes } from "node:crypto";
import { fetchBeacon, type ChainClient } from "drand-client";
import type { SqlClient } from "./db.js";
import { type Condition, ConditionError, canonicalJson, conditionHash, parseCondition, sealHash } from "./conditions.js";
import { KeyServiceError, isWrappedKey, type KeyWrapRegistry, type WrappedKey } from "./keywrap/types.js";
import type { KeyReleaser, ReleaseResponse } from "./verifier/protocol.js";

export const DAY_MS = 86_400_000;
export const MIN_FAILSAFE_MS = 30 * DAY_MS;
export const MAX_FAILSAFE_MS = 10 * 365 * DAY_MS;
export const DEK_LENGTH = 32;

export type LockStatus = "sealed" | "met" | "released" | "failsafe";

export interface LockView {
  vaultId: string;
  status: LockStatus;
  condition: Condition;
  conditionSha256: string;
  unlockAt: string | null;
  failsafeAt: string;
  createdAt: string;
  metAt: string | null;
  releasedAt: string | null;
  latestVerifierResult: { at: string; detail: Record<string, unknown> } | null;
}

export interface AuditEntry {
  id: number;
  event: string;
  detail: Record<string, unknown>;
  at: string;
}

/** An expected refusal, mapped to an HTTP status by the API layer. */
export class EscrowError extends Error {
  override name = "EscrowError";
  constructor(
    readonly status: 400 | 401 | 403 | 404 | 409 | 423 | 500 | 503,
    readonly code: string,
    message: string,
    readonly extra: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

export interface EscrowDeps {
  db: SqlClient;
  /** Wrap side only (KMS Encrypt). Decrypt happens in the verifier. */
  keys: KeyWrapRegistry;
  /** The key-release verifier, reached over its narrow interface (vsock / socket / in-process). */
  releaser: KeyReleaser;
  /** drand client used to fetch the latest beacon as time evidence for the verifier. */
  drand: ChainClient;
  /** The server's clock, for request freshness and lock validation. Never decides a release. */
  now?: () => Date;
}

interface LockRow {
  vault_id: string;
  condition_json: Condition;
  condition_sha256: string;
  wrapped_dek: WrappedKey;
  status: LockStatus;
  unlock_at: Date | null;
  failsafe_at: Date;
  created_at: Date;
  met_at: Date | null;
  released_at: Date | null;
}

const iso = (d: Date | null) => (d ? new Date(d).toISOString() : null);

export function isVaultId(v: string): boolean {
  return /^[0-9a-f]{32}$/.test(v);
}

export class Escrow {
  private readonly db: SqlClient;
  private readonly keys: KeyWrapRegistry;
  private readonly releaser: KeyReleaser;
  private readonly drand: ChainClient;
  readonly now: () => Date;

  constructor(deps: EscrowDeps) {
    this.db = deps.db;
    this.keys = deps.keys;
    this.releaser = deps.releaser;
    this.drand = deps.drand;
    this.now = deps.now ?? (() => new Date());
  }

  // ----- audit -----

  async audit(vaultId: string | null, event: string, detail: Record<string, unknown> = {}): Promise<void> {
    await this.db.query("insert into audit_log (vault_id, event, detail_json, at) values ($1, $2, $3::jsonb, $4)", [
      vaultId,
      event,
      JSON.stringify(detail),
      this.now(),
    ]);
  }

  async log(vaultId: string): Promise<AuditEntry[]> {
    await this.requireLock(vaultId);
    const { rows } = await this.db.query<{ id: number | string; event: string; detail_json: Record<string, unknown>; at: Date }>(
      "select id, event, detail_json, at from audit_log where vault_id = $1 order by id",
      [vaultId],
    );
    return rows.map((r) => ({ id: Number(r.id), event: r.event, detail: r.detail_json, at: iso(r.at)! }));
  }

  // ----- devices -----

  async registerDevice(publicKey: string, label = ""): Promise<{ deviceId: string }> {
    const deviceId = randomBytes(12).toString("base64url");
    try {
      await this.db.query("insert into devices (device_id, public_key, label, created_at) values ($1, $2, $3, $4)", [
        deviceId,
        publicKey,
        label.slice(0, 100),
        this.now(),
      ]);
    } catch (err) {
      if (/duplicate key|unique/i.test((err as Error).message)) {
        throw new EscrowError(409, "device-exists", "that public key is already registered");
      }
      throw err;
    }
    await this.audit(null, "device-registered", { deviceId, label });
    return { deviceId };
  }

  async devicePublicKey(deviceId: string): Promise<string | null> {
    const { rows } = await this.db.query<{ public_key: string }>(
      "select public_key from devices where device_id = $1 and revoked_at is null",
      [deviceId],
    );
    return rows[0]?.public_key ?? null;
  }

  /** Record a nonce; false if this device already used it (a replay). */
  async useNonce(deviceId: string, nonce: string, expiresAt: Date): Promise<boolean> {
    await this.db.query("delete from request_nonces where expires_at < $1", [this.now()]);
    const { rows } = await this.db.query(
      "insert into request_nonces (device_id, nonce, expires_at) values ($1, $2, $3) on conflict do nothing returning nonce",
      [deviceId, nonce, expiresAt],
    );
    return rows.length === 1;
  }

  // ----- locks -----

  async createLock(input: {
    vaultId: unknown;
    condition: unknown;
    failsafeAt: unknown;
    dek: unknown;
    deviceId: string;
  }): Promise<LockView> {
    const { vaultId, deviceId } = input;
    if (typeof vaultId !== "string" || !isVaultId(vaultId)) {
      throw new EscrowError(400, "bad-request", "vaultId must be 32 lowercase hex characters");
    }
    let condition: Condition;
    try {
      condition = parseCondition(input.condition);
    } catch (err) {
      if (err instanceof ConditionError) throw new EscrowError(400, "bad-condition", err.message);
      throw err;
    }
    if (typeof input.failsafeAt !== "string" || Number.isNaN(Date.parse(input.failsafeAt))) {
      throw new EscrowError(400, "bad-request", "failsafeAt must be an ISO 8601 time");
    }
    const failsafeAt = new Date(input.failsafeAt);
    const now = this.now().getTime();
    if (failsafeAt.getTime() < now + MIN_FAILSAFE_MS) {
      throw new EscrowError(400, "bad-failsafe", "the fail-safe must be at least 30 days away");
    }
    if (failsafeAt.getTime() > now + MAX_FAILSAFE_MS) {
      throw new EscrowError(400, "bad-failsafe", "the fail-safe can be at most 10 years away");
    }
    let unlockAt: Date | null = null;
    if (condition.type === "time") {
      unlockAt = new Date(condition.unlockAt);
      if (unlockAt.getTime() <= now) throw new EscrowError(400, "bad-condition", "unlockAt must be in the future");
      if (failsafeAt.getTime() < unlockAt.getTime()) {
        throw new EscrowError(400, "bad-failsafe", "the fail-safe can't be earlier than unlockAt");
      }
    }
    if (typeof input.dek !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(input.dek)) {
      throw new EscrowError(400, "bad-request", "dek must be 32 bytes, base64");
    }

    const dek = new Uint8Array(Buffer.from(input.dek, "base64"));
    let wrapped: WrappedKey;
    try {
      if (dek.length !== DEK_LENGTH) throw new EscrowError(400, "bad-request", "dek must be 32 bytes");
      if ((await this.db.query("select 1 from locks where vault_id = $1", [vaultId])).rows.length) {
        throw new EscrowError(409, "lock-exists", "a lock for this vault already exists");
      }
      wrapped = await this.keys.wrap(dek, { vaultId, seal: sealHash({ vaultId, condition, failsafeAt }) });
    } catch (err) {
      if (err instanceof KeyServiceError) throw new EscrowError(503, "key-service", "key service unavailable, nothing was stored");
      throw err;
    } finally {
      dek.fill(0);
    }

    const sha = conditionHash(condition);
    try {
      await this.db.query(
        `insert into locks (vault_id, condition_json, condition_sha256, wrapped_dek, status, unlock_at, failsafe_at, created_by_device, created_at)
         values ($1, $2::jsonb, $3, $4::jsonb, 'sealed', $5, $6, $7, $8)`,
        [vaultId, canonicalJson(condition), sha, JSON.stringify(wrapped), unlockAt, failsafeAt, deviceId, this.now()],
      );
    } catch (err) {
      if (/duplicate key|unique/i.test((err as Error).message)) {
        throw new EscrowError(409, "lock-exists", "a lock for this vault already exists");
      }
      throw err;
    }
    await this.audit(vaultId, "lock-created", {
      deviceId,
      conditionSha256: sha,
      conditionType: condition.type,
      failsafeAt: failsafeAt.toISOString(),
      keyScheme: wrapped.scheme,
    });
    return this.getLock(vaultId);
  }

  async getLock(vaultId: string): Promise<LockView> {
    const row = await this.requireLock(vaultId);
    const { rows } = await this.db.query<{ detail_json: Record<string, unknown>; at: Date }>(
      "select detail_json, at from audit_log where vault_id = $1 and event = 'verifier-check' order by id desc limit 1",
      [vaultId],
    );
    return {
      vaultId: row.vault_id,
      status: row.status,
      condition: row.condition_json,
      conditionSha256: row.condition_sha256,
      unlockAt: iso(row.unlock_at),
      failsafeAt: iso(row.failsafe_at)!,
      createdAt: iso(row.created_at)!,
      metAt: iso(row.met_at),
      releasedAt: iso(row.released_at),
      latestVerifierResult: rows[0] ? { at: iso(rows[0].at)!, detail: rows[0].detail_json } : null,
    };
  }

  /**
   * Ask the verifier to release the key, with the latest drand beacon as time evidence. The
   * verifier decides from the sealed terms and drand alone; this side enforces "only once" and
   * audits every request and outcome.
   */
  async unlock(vaultId: string, deviceId: string): Promise<{ dek: Uint8Array; via: "condition" | "failsafe" }> {
    const row = await this.requireLock(vaultId);
    await this.audit(vaultId, "unlock-requested", { deviceId });

    if (row.status === "released" || row.status === "failsafe") {
      await this.audit(vaultId, "unlock-denied", { deviceId, reason: "already-released" });
      throw new EscrowError(409, "already-released", "this key was already released once");
    }
    if (!isWrappedKey(row.wrapped_dek)) throw new Error("stored wrapped key is malformed");

    let beacon: { round: number; signature: string; randomness: string };
    try {
      const latest = await this.drand.latest();
      const b = await fetchBeacon(this.drand, latest.round);
      beacon = { round: b.round, signature: b.signature, randomness: b.randomness };
    } catch {
      await this.audit(vaultId, "unlock-failed", { deviceId, reason: "drand-unavailable" });
      throw new EscrowError(503, "drand-unavailable", "couldn't get time evidence from drand; try again");
    }

    let res: ReleaseResponse;
    try {
      res = await this.releaser.release({
        v: 1,
        vaultId,
        condition: row.condition_json,
        failsafeAt: iso(row.failsafe_at)!,
        wrappedDek: row.wrapped_dek,
        evidence: { drandBeacon: beacon },
      });
    } catch {
      await this.audit(vaultId, "unlock-failed", { deviceId, reason: "verifier-unavailable" });
      throw new EscrowError(503, "verifier-unavailable", "the key-release verifier is unavailable; try again");
    }

    if (!res.ok) {
      if (res.code === "still-locked") {
        await this.audit(vaultId, "unlock-denied", { deviceId, reason: "still-locked", drandRound: beacon.round });
        const d = res.detail ?? {};
        throw new EscrowError(423, "still-locked", "still locked", {
          reason: d.unlockAt
            ? `condition not met yet: unlocks at drand round ${String(d.unlockRound)} (${String(d.unlockAt)})`
            : `condition not met yet: waiting for the ${row.condition_json.type} verifier`,
          failsafeAt: iso(row.failsafe_at),
          drandRound: beacon.round,
          ...(d.unlockAt ? { unlockAt: d.unlockAt } : {}),
        });
      }
      await this.audit(vaultId, "unlock-failed", { deviceId, reason: res.code });
      if (res.code === "key-service" || res.code === "bad-evidence") {
        throw new EscrowError(503, res.code, `${res.message}; try again`);
      }
      throw new EscrowError(500, "unwrap-failed", "the verifier refused to release this key");
    }

    const dek = new Uint8Array(Buffer.from(res.dek, "base64"));
    const newStatus = res.via === "condition" ? "released" : "failsafe";
    const { rows } = await this.db.query(
      "update locks set status = $2, released_at = $3 where vault_id = $1 and status in ('sealed', 'met') returning vault_id",
      [vaultId, newStatus, this.now()],
    );
    if (rows.length !== 1) {
      dek.fill(0);
      await this.audit(vaultId, "unlock-denied", { deviceId, reason: "already-released" });
      throw new EscrowError(409, "already-released", "this key was already released once");
    }
    await this.audit(vaultId, "released", { deviceId, via: res.via, drandRound: beacon.round });
    return { dek, via: res.via };
  }

  /**
   * Bookkeeping for verifier jobs (milestone 5): records "met" with its evidence for status and
   * the log. Not exposed over HTTP, and not what releases a key: the verifier re-checks evidence
   * at release time.
   */
  async recordConditionMet(vaultId: string, evidence: Record<string, unknown>): Promise<boolean> {
    await this.requireLock(vaultId);
    const { rows } = await this.db.query(
      "update locks set status = 'met', met_at = $2 where vault_id = $1 and status = 'sealed' returning vault_id",
      [vaultId, this.now()],
    );
    if (rows.length === 1) await this.audit(vaultId, "condition-met", { evidence });
    return rows.length === 1;
  }

  /** Called by verifiers on every check, met or not; the latest is shown by GET /locks/:id. */
  async recordVerifierCheck(vaultId: string, detail: Record<string, unknown>): Promise<void> {
    await this.requireLock(vaultId);
    await this.audit(vaultId, "verifier-check", detail);
  }

  private async requireLock(vaultId: string): Promise<LockRow> {
    if (!isVaultId(vaultId)) throw new EscrowError(404, "not-found", "no such lock");
    const { rows } = await this.db.query<LockRow>("select * from locks where vault_id = $1", [vaultId]);
    if (!rows[0]) throw new EscrowError(404, "not-found", "no such lock");
    return rows[0];
  }
}
