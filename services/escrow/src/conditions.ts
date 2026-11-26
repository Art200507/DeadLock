/**
 * Sealed conditions. A condition is validated, canonicalised (sorted keys) and hashed when the
 * lock is created; the JSON and its SHA-256 are stored and never change. Verifiers (milestone 5)
 * read them to decide "met".
 */
import { createHash } from "node:crypto";

export interface TimeCondition {
  type: "time";
  /** UTC instant; the lock may be released at or after it by the server's own clock. */
  unlockAt: string;
}

export interface NflCondition {
  type: "nfl";
  /** The data provider's game ID (API-Sports), plus the scheduled kickoff for the polling window. */
  gameId: string;
  scheduledAt: string;
  /** Team that must win, as named by the provider. */
  team: string;
  outcome: "win";
  /** Sealed rules for games that don't finish normally. */
  ifTie: "stay-locked";
  ifPostponed: "stay-locked";
}

export type Condition = TimeCondition | NflCondition;

export class ConditionError extends Error {
  override name = "ConditionError";
}

const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;

function isoUtc(v: unknown, field: string): string {
  if (typeof v !== "string" || !ISO_UTC.test(v) || Number.isNaN(Date.parse(v))) {
    throw new ConditionError(`${field} must be a UTC ISO 8601 time like 2027-01-01T09:00:00Z`);
  }
  return new Date(v).toISOString();
}

function exactKeys(o: Record<string, unknown>, keys: string[]) {
  const extra = Object.keys(o).filter((k) => !keys.includes(k));
  if (extra.length) throw new ConditionError(`unknown condition field(s): ${extra.join(", ")}`);
}

/** Validate and normalise. Unknown fields are rejected so nothing unsealed rides along. */
export function parseCondition(input: unknown): Condition {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new ConditionError("condition must be an object");
  }
  const o = input as Record<string, unknown>;
  switch (o.type) {
    case "time":
      exactKeys(o, ["type", "unlockAt"]);
      return { type: "time", unlockAt: isoUtc(o.unlockAt, "unlockAt") };
    case "nfl": {
      exactKeys(o, ["type", "gameId", "scheduledAt", "team", "outcome", "ifTie", "ifPostponed"]);
      if (typeof o.gameId !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(o.gameId)) throw new ConditionError("gameId");
      if (typeof o.team !== "string" || o.team.trim().length === 0 || o.team.length > 100) throw new ConditionError("team");
      if (o.outcome !== "win") throw new ConditionError('outcome must be "win"');
      if (o.ifTie !== "stay-locked") throw new ConditionError('ifTie must be "stay-locked"');
      if (o.ifPostponed !== "stay-locked") throw new ConditionError('ifPostponed must be "stay-locked"');
      return {
        type: "nfl",
        gameId: o.gameId,
        scheduledAt: isoUtc(o.scheduledAt, "scheduledAt"),
        team: o.team.trim(),
        outcome: "win",
        ifTie: "stay-locked",
        ifPostponed: "stay-locked",
      };
    }
    default:
      throw new ConditionError(`unsupported condition type ${JSON.stringify(o.type)}`);
  }
}

/** JSON with keys sorted at every level: the exact bytes that are hashed. */
export function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v);
}

export function conditionHash(c: Condition): string {
  return createHash("sha256").update(canonicalJson(c)).digest("hex");
}

/**
 * The seal: a hash of everything that decides when a key may be released. It is part of the
 * key's encryption context, so the stored key only unwraps for exactly these terms.
 */
export function sealHash(terms: { vaultId: string; condition: Condition; failsafeAt: string | Date }): string {
  const canonical = canonicalJson({
    v: 1,
    vaultId: terms.vaultId,
    condition: terms.condition,
    failsafeAt: new Date(terms.failsafeAt).toISOString(),
  });
  return createHash("sha256").update(canonical).digest("hex");
}
