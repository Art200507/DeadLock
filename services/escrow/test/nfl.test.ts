/**
 * The NFL result verifier: provider parsing, the sealed rules (win/loss, tie, postponed,
 * cancelled), two-source agreement, and the full flow through the API, with the verifier
 * fetching both mock providers itself over TLS via the egress path.
 */
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { parseCondition, sealHash, type NflCondition } from "../src/conditions.js";
import { NflChecker } from "../src/verifiers/nfl.js";
import {
  ApiSportsNfl,
  SourceError,
  TheSportsDb,
  parseApiSportsGame,
  parseTheSportsDbEvent,
  type GameReport,
  type GameStatus,
  type SportsSource,
} from "../src/verifiers/sports.js";
import { SecretStore } from "../src/verifier/secrets.js";
import { pushSecrets } from "../src/verifier/transport.js";
import { DAY_MS, b64, harness, newDek, vaultId, type Harness } from "./helpers.js";
import { TEST_APISPORTS_KEY, TEST_THESPORTSDB_KEY, egressRig, type EgressRig } from "./helpers/sports.js";

const KICKOFF = "2026-12-07T18:00:00.000Z";
const AFTER = new Date(Date.parse(KICKOFF) + 4 * 3_600_000);

function nfl(over: Partial<NflCondition> = {}): NflCondition {
  return parseCondition({
    type: "nfl",
    game: { apiSportsId: "9001", theSportsDbId: "2077001", home: "Buffalo Bills", away: "Miami Dolphins", kickoffAt: KICKOFF },
    team: "Buffalo Bills",
    outcome: "win",
    ifTie: "stay-locked",
    ifPostponed: "wait",
    ifCancelled: "stay-locked",
    ...over,
  }) as NflCondition;
}

/** A fake source returning a fixed report (or throwing). */
function source(name: GameReport["source"], r: Partial<GameReport> | Error, calls?: { n: number }): SportsSource {
  return {
    name,
    async fetchGame(id) {
      if (calls) calls.n++;
      if (r instanceof Error) throw r;
      return { source: name, gameId: id, status: "final", rawStatus: "FT", home: "Buffalo Bills", away: "Miami Dolphins", homeScore: 27, awayScore: 20, ...r };
    },
  };
}

const both = (a: Partial<GameReport> | Error, b: Partial<GameReport> | Error = a as Partial<GameReport>) =>
  new NflChecker({ apiSports: source("api-sports", a), theSportsDb: source("thesportsdb", b) });

const final = (homeScore: number, awayScore: number): Partial<GameReport> => ({ status: "final", homeScore, awayScore });
const status = (s: GameStatus): Partial<GameReport> => ({ status: s, homeScore: null, awayScore: null });

describe("provider parsing", () => {
  const apiSports = (short: string, extra: Record<string, unknown> = {}) => ({
    get: "games",
    errors: [],
    results: 1,
    response: [
      {
        game: { id: 7803, status: { short, long: "x" } },
        teams: { home: { name: "Kansas City Chiefs" }, away: { name: "San Francisco 49ers" } },
        scores: { home: { total: 25 }, away: { total: 22 } },
        ...extra,
      },
    ],
  });

  it("API-Sports: maps status codes and totals", () => {
    const map: Record<string, GameStatus> = { NS: "scheduled", Q2: "in-progress", HT: "in-progress", OT: "in-progress", FT: "final", AOT: "final", PST: "postponed", CANC: "cancelled", XYZ: "unknown" };
    for (const [short, want] of Object.entries(map)) assert.equal(parseApiSportsGame(apiSports(short), "7803").status, want, short);
    const r = parseApiSportsGame(apiSports("AOT"), "7803");
    assert.deepEqual([r.home, r.away, r.homeScore, r.awayScore], ["Kansas City Chiefs", "San Francisco 49ers", 25, 22]);
  });

  it("API-Sports: errors, no game or a different game are errors, not results", () => {
    assert.throws(() => parseApiSportsGame({ errors: { token: "Error/Missing application key." }, response: [] }, "7803"), SourceError);
    assert.throws(() => parseApiSportsGame({ errors: { plan: "Free plans do not have access to this season" }, response: [] }, "7803"), SourceError);
    assert.throws(() => parseApiSportsGame({ errors: [], response: [] }, "7803"), /0 games/);
    assert.throws(() => parseApiSportsGame(apiSports("FT"), "1"), /different game/);
  });

  it("TheSportsDB: real field names, string scores, postponed flag, API-Sports cross-reference", () => {
    const ev = (o: Record<string, unknown>) => ({
      events: [{ idEvent: "1942349", idAPIfootball: "7803", strHomeTeam: "Kansas City Chiefs", strAwayTeam: "San Francisco 49ers", intHomeScore: "25", intAwayScore: "22", strStatus: "FT", strPostponed: "no", ...o }],
    });
    const r = parseTheSportsDbEvent(ev({}), "1942349");
    assert.deepEqual([r.status, r.homeScore, r.awayScore, r.apiSportsId], ["final", 25, 22, "7803"]);
    assert.equal(parseTheSportsDbEvent(ev({ strStatus: "Match Finished" }), "1942349").status, "final");
    assert.equal(parseTheSportsDbEvent(ev({ strStatus: "Not Started", intHomeScore: null }), "1942349").status, "scheduled");
    assert.equal(parseTheSportsDbEvent(ev({ strStatus: "NS", strPostponed: "yes" }), "1942349").status, "postponed");
    assert.equal(parseTheSportsDbEvent(ev({ strStatus: "Cancelled" }), "1942349").status, "cancelled");
    assert.equal(parseTheSportsDbEvent(ev({ strStatus: "Q3" }), "1942349").status, "in-progress");
    assert.throws(() => parseTheSportsDbEvent({ events: null }, "1942349"), SourceError);
    assert.throws(() => parseTheSportsDbEvent(ev({}), "1"), /different event/);
  });
});

describe("sealed NFL conditions", () => {
  it("validates the game, the team and every rule", () => {
    assert.equal(nfl().ifPostponed, "wait");
    assert.throws(() => nfl({ team: "New York Jets" }), /home or away/);
    assert.throws(() => parseCondition({ ...nfl(), ifTie: "flip-a-coin" }), /ifTie/);
    assert.throws(() => parseCondition({ ...nfl(), game: { ...nfl().game, apiSportsId: "abc" } }), /numeric/);
    assert.throws(() => parseCondition({ ...nfl(), extra: 1 }), /unknown condition field/);
    assert.throws(() => parseCondition({ ...nfl(), game: { ...nfl().game, away: "buffalo bills" } }), /differ/);
  });

  it("every rule is part of the seal", () => {
    const v = vaultId();
    const f = "2027-12-01T00:00:00.000Z";
    const base = sealHash({ vaultId: v, condition: nfl(), failsafeAt: f });
    for (const over of [{ ifTie: "unlock" }, { ifCancelled: "unlock" }, { ifPostponed: "stay-locked" }, { outcome: "loss" }, { team: "Miami Dolphins" }] as Partial<NflCondition>[]) {
      assert.notEqual(sealHash({ vaultId: v, condition: nfl(over), failsafeAt: f }), base, JSON.stringify(over));
    }
  });
});

describe("NFL decisions (both sources must agree)", () => {
  it("win → met; loss → resolved, not met; a 'loss' lock opens on a loss", async () => {
    assert.equal((await both(final(27, 20)).check(nfl(), AFTER)).state, "met");
    const lost = await both(final(17, 20)).check(nfl(), AFTER);
    assert.deepEqual([lost.state, lost.state === "not-met" && lost.resolved], ["not-met", true]);
    assert.equal((await both(final(17, 20)).check(nfl({ outcome: "loss" }), AFTER)).state, "met");
    assert.equal((await both(final(17, 20)).check(nfl({ team: "Miami Dolphins" }), AFTER)).state, "met", "away team won");
  });

  it("tie follows ifTie", async () => {
    assert.equal((await both(final(20, 20)).check(nfl({ ifTie: "unlock" }), AFTER)).state, "met");
    const v = await both(final(20, 20)).check(nfl({ ifTie: "stay-locked" }), AFTER);
    assert.ok(v.state === "not-met" && v.resolved && /tie/.test(v.reason));
  });

  it("postponed follows ifPostponed; cancelled follows ifCancelled", async () => {
    const p = await both(status("postponed")).check(nfl({ ifPostponed: "wait" }), AFTER);
    assert.ok(p.state === "not-met" && !p.resolved && /rescheduled/.test(p.reason));
    assert.equal((await both(status("postponed")).check(nfl({ ifPostponed: "unlock" }), AFTER)).state, "met");
    const pl = await both(status("postponed")).check(nfl({ ifPostponed: "stay-locked" }), AFTER);
    assert.ok(pl.state === "not-met" && pl.resolved);
    assert.equal((await both(status("cancelled")).check(nfl({ ifCancelled: "unlock" }), AFTER)).state, "met");
    const cl = await both(status("cancelled")).check(nfl({ ifCancelled: "stay-locked" }), AFTER);
    assert.ok(cl.state === "not-met" && cl.resolved);
  });

  it("waits while a source lags; terminal states or final scores that differ are a disagreement", async () => {
    const lag = await both(final(27, 20), status("in-progress")).check(nfl(), AFTER);
    assert.ok(lag.state === "not-met" && !lag.resolved && /waiting for both/.test(lag.reason));
    assert.equal((await both(final(27, 20), status("postponed")).check(nfl(), AFTER)).state, "disagree");
    const scores = await both(final(27, 20), final(20, 27)).check(nfl(), AFTER);
    assert.ok(scores.state === "disagree" && /scores differ/.test(scores.reason));
    assert.equal((await both({ status: "final", homeScore: null, awayScore: null }).check(nfl(), AFTER)).state, "not-met");
  });

  it("a source describing another game is a disagreement", async () => {
    const teams = await both(final(27, 20), { ...final(27, 20), home: "New York Jets" }).check(nfl(), AFTER);
    assert.ok(teams.state === "disagree" && /not the sealed game/.test(teams.reason));
    const link = await both(final(27, 20), { ...final(27, 20), apiSportsId: "1234" }).check(nfl(), AFTER);
    assert.ok(link.state === "disagree" && /different api-sports game/.test(link.reason));
  });

  it("either source failing means unavailable, never a release", async () => {
    const v = await both(final(27, 20), new SourceError("thesportsdb HTTP 502")).check(nfl(), AFTER);
    assert.ok(v.state === "unavailable" && /thesportsdb HTTP 502/.test(v.reason));
  });

  it("before kickoff by drand time: not met, and no API calls", async () => {
    const calls = { n: 0 };
    const c = new NflChecker({ apiSports: source("api-sports", final(27, 20), calls), theSportsDb: source("thesportsdb", final(27, 20), calls) });
    const v = await c.check(nfl(), new Date(Date.parse(KICKOFF) - 60_000));
    assert.ok(v.state === "not-met" && /kicked off/.test(v.reason));
    assert.equal(calls.n, 0);
  });
});

describe("NFL locks end to end (verifier fetches both providers over TLS through the egress path)", () => {
  let rig: EgressRig;
  let h: Harness;
  const secrets = new SecretStore();
  const GAME = { apiSportsId: "9001", theSportsDbId: "2077001", home: "Buffalo Bills", away: "Miami Dolphins" };
  const condition = (over: Record<string, unknown> = {}) => ({
    type: "nfl",
    game: { ...GAME, kickoffAt: KICKOFF },
    team: "Buffalo Bills",
    outcome: "win",
    ifTie: "stay-locked",
    ifPostponed: "wait",
    ifCancelled: "stay-locked",
    ...over,
  });
  const lockBody = (over: Record<string, unknown> = {}, dek = newDek()) => ({
    vaultId: vaultId(),
    condition: condition(over),
    failsafeAt: new Date(h.clock.now.getTime() + 60 * DAY_MS).toISOString(),
    dek: b64(dek),
  });

  before(async () => {
    rig = await egressRig();
    const nflChecker = new NflChecker({
      apiSports: new ApiSportsNfl({ http: rig.http, apiKey: secrets.apiSportsKey }),
      theSportsDb: new TheSportsDb({ http: rig.http, apiKey: secrets.theSportsDbKey }),
    });
    h = await harness({ enclave: true, socket: true, nfl: nflChecker, secrets });
    rig.sports.set({ ...GAME, apiStatus: "NS", tsdbStatus: "NS", homeScore: null, awayScore: null });
  });
  after(async () => {
    await h.close();
    await rig.close();
  });

  it("is still locked before kickoff, without calling either provider", async () => {
    const body = lockBody();
    assert.equal((await h.call("POST", "/locks", body)).status, 201);
    const callsBefore = rig.sports.requests.length;
    const res = await h.call("POST", `/locks/${body.vaultId}/unlock`);
    assert.equal(res.status, 423);
    assert.match(res.json.reason, /hasn't kicked off/);
    assert.equal(rig.sports.requests.length, callsBefore);
  });

  it("follows the game to a win: needs keys, waits for both sources, then releases once", async () => {
    const dek = newDek();
    const body = lockBody({}, dek);
    await h.call("POST", "/locks", body);
    h.setTime(Date.parse(KICKOFF) + 30 * 60_000);
    const unlock = () => h.call("POST", `/locks/${body.vaultId}/unlock`);

    // No API keys in the verifier yet.
    let res = await unlock();
    assert.equal(res.status, 503);
    assert.equal(res.json.error, "sources-unavailable");

    // The parent delivers them over the verifier socket.
    const pushed = await pushSecrets({ path: h.socketPath! }, { v: 1, op: "secrets", sports: { apiSportsKey: TEST_APISPORTS_KEY, theSportsDbKey: TEST_THESPORTSDB_KEY } });
    assert.ok(pushed.ok);

    rig.sports.update("9001", { apiStatus: "Q3", tsdbStatus: "Q3", homeScore: 17, awayScore: 10 });
    res = await unlock();
    assert.equal(res.status, 423);
    assert.match(res.json.reason, /in-progress/);

    rig.sports.update("9001", { apiStatus: "FT", tsdbStatus: "Q4", homeScore: 27, awayScore: 20 });
    res = await unlock();
    assert.equal(res.status, 423);
    assert.match(res.json.reason, /waiting for both sources/);

    rig.sports.update("9001", { tsdbStatus: "FT" });
    res = await unlock();
    assert.equal(res.status, 200, JSON.stringify(res.json));
    assert.equal(res.json.via, "condition");
    assert.equal(res.json.dek, b64(dek));
    assert.match(res.json.detail.reason, /Buffalo Bills won as sealed/);
    assert.equal((await unlock()).status, 409);

    const view = await h.call("GET", `/locks/${body.vaultId}`);
    assert.equal(view.json.status, "released");
    assert.equal(view.json.latestVerifierResult.detail.outcome, "met");
    assert.equal(view.json.latestVerifierResult.detail.reports.length, 2);
    const keyHeaders = rig.sports.requests.filter((r) => r.headers["x-apisports-key"] === TEST_APISPORTS_KEY);
    assert.ok(keyHeaders.length > 0, "the verifier called API-Sports with the delivered key");
  });

  it("disagreeing sources keep it locked and say so", async () => {
    const body = lockBody();
    await h.call("POST", "/locks", body);
    rig.sports.update("9001", { apiStatus: "FT", tsdbStatus: "FT", homeScore: 27, awayScore: 20, tsdbHomeScore: 20, tsdbAwayScore: 27 });
    const res = await h.call("POST", `/locks/${body.vaultId}/unlock`);
    assert.equal(res.status, 423);
    assert.equal(res.json.sourcesDisagree, true);
    assert.match(res.json.reason, /scores differ/);
    rig.sports.update("9001", { tsdbHomeScore: undefined, tsdbAwayScore: undefined });
  });

  it("the API host can't flip the result: no score input exists, and an edited condition doesn't unwrap", async () => {
    const body = lockBody({ team: "Miami Dolphins" }); // Dolphins must win; they lose 20-27 below
    await h.call("POST", "/locks", body);
    rig.sports.update("9001", { apiStatus: "FT", tsdbStatus: "FT", homeScore: 27, awayScore: 20 });
    const { rows } = await h.db.query<{ wrapped_dek: any; failsafe_at: Date }>("select wrapped_dek, failsafe_at from locks where vault_id = $1", [body.vaultId]);
    const latest = await h.drand.latest();
    const beacon = { round: latest.round, signature: latest.signature, randomness: latest.randomness };
    const base = { v: 1 as const, vaultId: body.vaultId, failsafeAt: rows[0]!.failsafe_at.toISOString(), wrappedDek: rows[0]!.wrapped_dek };

    // A forged "scores" field is ignored: the verifier fetches its own.
    const forged = await h.verifier.release({ ...base, condition: body.condition, evidence: { drandBeacon: beacon, scores: { home: 0, away: 99 } } } as any);
    assert.equal(forged.ok, false);
    assert.equal(!forged.ok && forged.code, "still-locked");
    // Swapping the team to the winner changes the seal, so even the attested enclave can't unwrap.
    const edited = await h.verifier.release({ ...base, condition: { ...body.condition, team: "Buffalo Bills" }, evidence: { drandBeacon: beacon } });
    assert.equal(!edited.ok && edited.code, "unwrap-failed");
  });
  // Last: it moves drand past this lock's fail-safe, and drand never runs backwards.
  it("a loss stays locked (resolved), then opens via the fail-safe without asking either provider", async () => {
    rig.sports.update("9001", { apiStatus: "FT", tsdbStatus: "FT", homeScore: 13, awayScore: 24 });
    h.setTime(Date.parse(KICKOFF) + 5 * 3_600_000);
    const dek = newDek();
    const body = { ...lockBody({}, dek), failsafeAt: new Date(Date.parse(KICKOFF) + 40 * DAY_MS).toISOString() };
    assert.equal((await h.call("POST", "/locks", body)).status, 201);
    let res = await h.call("POST", `/locks/${body.vaultId}/unlock`);
    assert.equal(res.status, 423);
    assert.equal(res.json.resolved, true);
    assert.match(res.json.reason, /only the fail-safe opens it/);

    h.setTime(Date.parse(body.failsafeAt) + 5000);
    const callsBefore = rig.sports.requests.length;
    res = await h.call("POST", `/locks/${body.vaultId}/unlock`);
    assert.equal(res.status, 200);
    assert.equal(res.json.via, "failsafe");
    assert.equal(res.json.dek, b64(dek));
    assert.equal(rig.sports.requests.length, callsBefore, "the fail-safe needs no provider");
  });

});
