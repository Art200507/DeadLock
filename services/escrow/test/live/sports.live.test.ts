/**
 * Optional live check against the real API-Sports and TheSportsDB free tiers. Not part of
 * `pnpm test`; you enable it with your own keys in services/escrow/.env (git-ignored):
 *
 *   CONDLOCK_LIVE_SPORTS=1
 *   APISPORTS_KEY=...            # free account at api-sports.io (American Football API)
 *   THESPORTSDB_KEY=123          # TheSportsDB's public free key, or your own
 *   pnpm --filter @condlock/escrow test:live-sports
 *
 * Default game: Super Bowl LVIII (2024-02-11), Kansas City Chiefs 25, San Francisco 49ers 22 (OT).
 * Override with CONDLOCK_LIVE_APISPORTS_ID / CONDLOCK_LIVE_THESPORTSDB_ID / CONDLOCK_LIVE_HOME /
 * CONDLOCK_LIVE_AWAY. About 3 requests to each API. Uses Node's bundled CA roots and a direct
 * connection (no enclave); the parsing and decision code is the same the verifier runs.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parseCondition, type NflCondition } from "../../src/conditions.js";
import { DirectDialer } from "../../src/egress/dialer.js";
import { EgressHttps } from "../../src/egress/https.js";
import { NflChecker } from "../../src/verifiers/nfl.js";
import { ApiSportsNfl, TheSportsDb } from "../../src/verifiers/sports.js";

const env = process.env;
const enabled = env.CONDLOCK_LIVE_SPORTS === "1" && env.APISPORTS_KEY && env.THESPORTSDB_KEY;
const skip = enabled ? false : "set CONDLOCK_LIVE_SPORTS=1, APISPORTS_KEY and THESPORTSDB_KEY (see services/escrow/README.md)";

const game = {
  apiSportsId: env.CONDLOCK_LIVE_APISPORTS_ID ?? "7803",
  theSportsDbId: env.CONDLOCK_LIVE_THESPORTSDB_ID ?? "1942349",
  home: env.CONDLOCK_LIVE_HOME ?? "Kansas City Chiefs",
  away: env.CONDLOCK_LIVE_AWAY ?? "San Francisco 49ers",
  kickoffAt: "2000-01-01T00:00:00Z",
};

describe("live sports APIs [manual]", { skip }, () => {
  const http = new EgressHttps({ dialer: new DirectDialer() });
  const apiSports = new ApiSportsNfl({ http, apiKey: () => env.APISPORTS_KEY });
  const theSportsDb = new TheSportsDb({ http, apiKey: () => env.THESPORTSDB_KEY });
  const checker = new NflChecker({ apiSports, theSportsDb });
  const cond = (team: string) =>
    parseCondition({ type: "nfl", game, team, outcome: "win", ifTie: "stay-locked", ifPostponed: "wait", ifCancelled: "stay-locked" }) as NflCondition;

  it("both providers return the game, and they agree on the final", async () => {
    const [a, b] = await Promise.all([apiSports.fetchGame(game.apiSportsId), theSportsDb.fetchGame(game.theSportsDbId)]);
    console.log("api-sports:", JSON.stringify(a));
    console.log("thesportsdb:", JSON.stringify(b));
    assert.equal(a.status, "final");
    assert.equal(b.status, "final");
    assert.deepEqual([a.homeScore, a.awayScore], [b.homeScore, b.awayScore]);
  });

  it("the checker unlocks for the winner and resolves 'not met' for the loser", async () => {
    const forHome = await checker.check(cond(game.home), new Date());
    const forAway = await checker.check(cond(game.away), new Date());
    console.log("home:", forHome.state, forHome.reason);
    console.log("away:", forAway.state, forAway.reason);
    const states = [forHome.state, forAway.state].sort();
    assert.deepEqual(states, ["met", "not-met"], "exactly one side won (a tie would make both not-met)");
  });
});
