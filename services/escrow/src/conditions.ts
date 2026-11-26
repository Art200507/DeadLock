/**
 * Sealed conditions. A condition is validated, canonicalised (sorted keys) and hashed when the
 * lock is created; the JSON and its SHA-256 are stored and never change. The key-release verifier
 * reads them (from the request, re-validated) to decide "met": src/verifiers/.
 */
import { createHash } from "node:crypto";

export interface TimeCondition {
  type: "time";
  /** UTC instant; released once a verified drand beacon for that time exists. */
  unlockAt: string;
}

export interface NflGame {
  /** API-Sports (american-football v1) game ID. */
  apiSportsId: string;
  /** TheSportsDB event ID for the same game. */
  theSportsDbId: string;
  /** Team names as both providers spell them (compared case- and punctuation-insensitively). */
  home: string;
  away: string;
  /** Scheduled kickoff (UTC). A "final" is only accepted once drand time is past it. */
  kickoffAt: string;
}

export interface NflCondition {
  type: "nfl";
  game: NflGame;
  /** Must be game.home or game.away. */
  team: string;
  /** Unlock when `team` wins, or when it loses. */
  outcome: "win" | "loss";
  /** Sealed rules for games that don't end in a win or loss. "stay-locked" = only the fail-safe opens it. */
  ifTie: "unlock" | "stay-locked";
  /** "wait" keeps waiting for the rescheduled game (same IDs). */
  ifPostponed: "wait" | "unlock" | "stay-locked";
  ifCancelled: "unlock" | "stay-locked";
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
      exactKeys(o, ["type", "game", "team", "outcome", "ifTie", "ifPostponed", "ifCancelled"]);
      const g = o.game as Record<string, unknown>;
      if (typeof g !== "object" || g === null || Array.isArray(g)) throw new ConditionError("game must be an object");
      exactKeys(g, ["apiSportsId", "theSportsDbId", "home", "away", "kickoffAt"]);
      const id = (v: unknown, f: string) => {
        if (typeof v !== "string" || !/^[0-9]{1,12}$/.test(v)) throw new ConditionError(`game.${f} must be a numeric ID string`);
        return v;
      };
      const name = (v: unknown, f: string) => {
        if (typeof v !== "string" || v.trim().length === 0 || v.length > 100) throw new ConditionError(f);
        return v.trim().replace(/\s+/g, " ");
      };
      const game: NflGame = {
        apiSportsId: id(g.apiSportsId, "apiSportsId"),
        theSportsDbId: id(g.theSportsDbId, "theSportsDbId"),
        home: name(g.home, "game.home"),
        away: name(g.away, "game.away"),
        kickoffAt: isoUtc(g.kickoffAt, "game.kickoffAt"),
      };
      if (teamKey(game.home) === teamKey(game.away)) throw new ConditionError("home and away must differ");
      const team = name(o.team, "team");
      if (teamKey(team) !== teamKey(game.home) && teamKey(team) !== teamKey(game.away)) {
        throw new ConditionError("team must be the game's home or away team");
      }
      const oneOf = <T extends string>(v: unknown, f: string, allowed: readonly T[]): T => {
        if (!allowed.includes(v as T)) throw new ConditionError(`${f} must be one of ${allowed.map((a) => `"${a}"`).join(", ")}`);
        return v as T;
      };
      return {
        type: "nfl",
        game,
        team,
        outcome: oneOf(o.outcome, "outcome", ["win", "loss"] as const),
        ifTie: oneOf(o.ifTie, "ifTie", ["unlock", "stay-locked"] as const),
        ifPostponed: oneOf(o.ifPostponed, "ifPostponed", ["wait", "unlock", "stay-locked"] as const),
        ifCancelled: oneOf(o.ifCancelled, "ifCancelled", ["unlock", "stay-locked"] as const),
      };
    }
    default:
      throw new ConditionError(`unsupported condition type ${JSON.stringify(o.type)}`);
  }
}

/** Team names compare case- and punctuation-insensitively ("San Francisco 49ers" = "san francisco 49ers"). */
export function teamKey(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, "");
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
