/**
 * The two NFL result sources, each fetched by the verifier itself over TLS (src/egress), never
 * via the API host. Both are normalised to a GameReport; the NFL checker requires them to agree.
 *
 *  - API-Sports, American Football v1: GET https://v1.american-football.api-sports.io/games?id=ID
 *    with header x-apisports-key. Status codes: NS, Q1-Q4, OT, HT, FT, AOT, CANC, PST.
 *  - TheSportsDB v1: GET https://www.thesportsdb.com/api/v1/json/{key}/lookupevent.php?id=ID.
 *    strStatus ("FT", "AOT", "NS", "Postponed", ...), strPostponed, intHomeScore (strings).
 *    It also cross-references API-Sports' ID as idAPIfootball.
 */
import type { EgressHttps } from "../egress/https.js";

export type GameStatus = "scheduled" | "in-progress" | "final" | "postponed" | "cancelled" | "unknown";

export interface GameReport {
  source: "api-sports" | "thesportsdb";
  gameId: string;
  status: GameStatus;
  rawStatus: string;
  home: string;
  away: string;
  homeScore: number | null;
  awayScore: number | null;
  /** TheSportsDB only: the API-Sports ID it links to, if it has one. */
  apiSportsId?: string;
}

export interface SportsSource {
  readonly name: GameReport["source"];
  fetchGame(id: string): Promise<GameReport>;
}

export class SourceError extends Error {
  override name = "SourceError";
}

function score(v: unknown): number | null {
  if (typeof v === "number" && Number.isInteger(v) && v >= 0) return v;
  if (typeof v === "string" && /^\d{1,3}$/.test(v)) return Number(v);
  return null;
}

const API_SPORTS_STATUS: Record<string, GameStatus> = {
  NS: "scheduled",
  TBD: "scheduled",
  Q1: "in-progress",
  Q2: "in-progress",
  Q3: "in-progress",
  Q4: "in-progress",
  OT: "in-progress",
  HT: "in-progress",
  BT: "in-progress",
  FT: "final",
  AOT: "final",
  PST: "postponed",
  CANC: "cancelled",
};

/** Exported for tests and the live check. */
export function parseApiSportsGame(json: unknown, id: string): GameReport {
  const body = json as { errors?: unknown; response?: unknown[] };
  const errors = body?.errors;
  const hasErrors = Array.isArray(errors) ? errors.length > 0 : errors && typeof errors === "object" && Object.keys(errors).length > 0;
  if (hasErrors) throw new SourceError(`api-sports error: ${JSON.stringify(errors).slice(0, 200)}`);
  const games = Array.isArray(body?.response) ? body.response : [];
  if (games.length !== 1) throw new SourceError(`api-sports returned ${games.length} games for id ${id}`);
  const g = games[0] as {
    game?: { id?: unknown; status?: { short?: unknown } };
    teams?: { home?: { name?: unknown }; away?: { name?: unknown } };
    scores?: { home?: { total?: unknown }; away?: { total?: unknown } };
  };
  if (String(g.game?.id) !== id) throw new SourceError("api-sports returned a different game");
  const home = g.teams?.home?.name;
  const away = g.teams?.away?.name;
  if (typeof home !== "string" || typeof away !== "string") throw new SourceError("api-sports: missing team names");
  const raw = typeof g.game?.status?.short === "string" ? g.game.status.short : "";
  return {
    source: "api-sports",
    gameId: id,
    status: API_SPORTS_STATUS[raw.toUpperCase()] ?? "unknown",
    rawStatus: raw,
    home,
    away,
    homeScore: score(g.scores?.home?.total),
    awayScore: score(g.scores?.away?.total),
  };
}

function theSportsDbStatus(raw: string, postponed: unknown): GameStatus {
  if (typeof postponed === "string" && postponed.toLowerCase() === "yes") return "postponed";
  const s = raw.trim().toLowerCase();
  if (["ft", "aot", "aet", "match finished", "finished", "final"].includes(s)) return "final";
  if (["ns", "not started", "tbd", "time to be defined", ""].includes(s)) return "scheduled";
  if (["postponed", "pst"].includes(s)) return "postponed";
  if (["cancelled", "canceled", "canc", "abandoned"].includes(s)) return "cancelled";
  if (/^(q[1-4]|ot|ht|bt|1h|2h|in progress|live)$/.test(s)) return "in-progress";
  return "unknown";
}

export function parseTheSportsDbEvent(json: unknown, id: string): GameReport {
  const events = (json as { events?: unknown })?.events;
  if (!Array.isArray(events) || events.length !== 1) throw new SourceError(`thesportsdb has no single event ${id}`);
  const e = events[0] as Record<string, unknown>;
  if (String(e.idEvent) !== id) throw new SourceError("thesportsdb returned a different event");
  if (typeof e.strHomeTeam !== "string" || typeof e.strAwayTeam !== "string") throw new SourceError("thesportsdb: missing team names");
  const raw = typeof e.strStatus === "string" ? e.strStatus : "";
  return {
    source: "thesportsdb",
    gameId: id,
    status: theSportsDbStatus(raw, e.strPostponed),
    rawStatus: raw,
    home: e.strHomeTeam,
    away: e.strAwayTeam,
    homeScore: score(e.intHomeScore),
    awayScore: score(e.intAwayScore),
    ...(typeof e.idAPIfootball === "string" && /^\d+$/.test(e.idAPIfootball) ? { apiSportsId: e.idAPIfootball } : {}),
  };
}

export interface SourceOptions {
  http: EgressHttps;
  /** Read at request time, so keys delivered into the enclave after start-up are used. */
  apiKey: () => string | undefined;
  baseUrl?: string;
}

export class ApiSportsNfl implements SportsSource {
  readonly name = "api-sports";
  constructor(private readonly opts: SourceOptions) {}

  async fetchGame(id: string): Promise<GameReport> {
    const key = this.opts.apiKey();
    if (!key) throw new SourceError("no API-Sports key has been delivered to the verifier");
    const base = this.opts.baseUrl ?? "https://v1.american-football.api-sports.io";
    const { status, json } = await this.opts.http.getJson(`${base}/games?id=${encodeURIComponent(id)}`, { "x-apisports-key": key });
    if (status !== 200) throw new SourceError(`api-sports HTTP ${status}`);
    return parseApiSportsGame(json, id);
  }
}

export class TheSportsDb implements SportsSource {
  readonly name = "thesportsdb";
  constructor(private readonly opts: SourceOptions) {}

  async fetchGame(id: string): Promise<GameReport> {
    const key = this.opts.apiKey();
    if (!key) throw new SourceError("no TheSportsDB key has been delivered to the verifier");
    const base = this.opts.baseUrl ?? "https://www.thesportsdb.com";
    const { status, json } = await this.opts.http.getJson(
      `${base}/api/v1/json/${encodeURIComponent(key)}/lookupevent.php?id=${encodeURIComponent(id)}`,
    );
    if (status !== 200) throw new SourceError(`thesportsdb HTTP ${status}`);
    return parseTheSportsDbEvent(json, id);
  }
}
