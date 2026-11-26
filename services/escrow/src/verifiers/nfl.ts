/**
 * The NFL result verifier. Runs inside the key-release verifier; fetches both sources itself and
 * decides from the sealed rules. Nothing comes from the API host except the (re-validated,
 * seal-bound) condition.
 *
 *   - Before kickoff by drand time: not met, and no API calls.
 *   - Either source unreachable or erroring: "unavailable" (try later; never a release).
 *   - Sources naming different teams, or linking different game IDs: "disagree".
 *   - Both must report the same terminal state (final / postponed / cancelled); if one still
 *     says scheduled or in progress, wait. Different terminal states, or different final scores:
 *     "disagree" (stays locked; a later check may see corrected data).
 *   - Final: tie → ifTie; otherwise `team` won or lost → met if that's the sealed outcome, else
 *     resolved-not-met (only the fail-safe opens it).
 *   - Postponed → ifPostponed ("wait" keeps checking), cancelled → ifCancelled.
 */
import { teamKey, type NflCondition } from "../conditions.js";
import type { GameReport, SportsSource } from "./sports.js";

export type NflVerdict =
  | { state: "met"; reason: string; reports: GameReport[] }
  /** resolved: the game is over and the sealed outcome didn't happen; only the fail-safe opens it. */
  | { state: "not-met"; resolved: boolean; reason: string; reports: GameReport[] }
  | { state: "disagree"; reason: string; reports: GameReport[] }
  | { state: "unavailable"; reason: string };

const TERMINAL = new Set(["final", "postponed", "cancelled"]);

export class NflChecker {
  constructor(private readonly sources: { apiSports: SportsSource; theSportsDb: SportsSource }) {}

  /** `verifiedNow`: the time proven by a BLS-verified drand beacon (not a clock). */
  async check(c: NflCondition, verifiedNow: Date): Promise<NflVerdict> {
    if (verifiedNow.getTime() < Date.parse(c.game.kickoffAt)) {
      return { state: "not-met", resolved: false, reason: `the game hasn't kicked off (kickoff ${c.game.kickoffAt})`, reports: [] };
    }
    const settled = await Promise.allSettled([
      this.sources.apiSports.fetchGame(c.game.apiSportsId),
      this.sources.theSportsDb.fetchGame(c.game.theSportsDbId),
    ]);
    const failed = settled.flatMap((s, i) =>
      s.status === "rejected" ? [`${i === 0 ? "api-sports" : "thesportsdb"}: ${(s.reason as Error)?.message ?? "error"}`] : [],
    );
    if (failed.length) return { state: "unavailable", reason: `both sources are required; ${failed.join("; ")}` };
    const [a, b] = settled.map((s) => (s as PromiseFulfilledResult<GameReport>).value) as [GameReport, GameReport];
    const reports = [a, b];

    for (const r of reports) {
      if (teamKey(r.home) !== teamKey(c.game.home) || teamKey(r.away) !== teamKey(c.game.away)) {
        return { state: "disagree", reason: `${r.source} reports ${r.away} at ${r.home}, not the sealed game`, reports };
      }
    }
    if (b.apiSportsId && b.apiSportsId !== c.game.apiSportsId) {
      return { state: "disagree", reason: "thesportsdb links this event to a different api-sports game", reports };
    }

    if (a.status !== b.status) {
      if (TERMINAL.has(a.status) && TERMINAL.has(b.status)) {
        return { state: "disagree", reason: `api-sports says ${a.status}, thesportsdb says ${b.status}`, reports };
      }
      return {
        state: "not-met",
        resolved: false,
        reason: `waiting for both sources to agree (api-sports: ${a.status}, thesportsdb: ${b.status})`,
        reports,
      };
    }

    switch (a.status) {
      case "scheduled":
      case "in-progress":
      case "unknown":
        return { state: "not-met", resolved: false, reason: `game is ${a.status}`, reports };
      case "postponed":
        if (c.ifPostponed === "wait") return { state: "not-met", resolved: false, reason: "postponed; waiting for the rescheduled game", reports };
        return c.ifPostponed === "unlock"
          ? { state: "met", reason: "postponed, and the sealed rule unlocks on postponement", reports }
          : { state: "not-met", resolved: true, reason: "postponed; the sealed rule keeps it locked until the fail-safe", reports };
      case "cancelled":
        return c.ifCancelled === "unlock"
          ? { state: "met", reason: "cancelled, and the sealed rule unlocks on cancellation", reports }
          : { state: "not-met", resolved: true, reason: "cancelled; the sealed rule keeps it locked until the fail-safe", reports };
      case "final": {
        if (a.homeScore === null || a.awayScore === null || b.homeScore === null || b.awayScore === null) {
          return { state: "not-met", resolved: false, reason: "final, but a source has no score yet", reports };
        }
        if (a.homeScore !== b.homeScore || a.awayScore !== b.awayScore) {
          return {
            state: "disagree",
            reason: `final scores differ (api-sports ${a.homeScore}-${a.awayScore}, thesportsdb ${b.homeScore}-${b.awayScore})`,
            reports,
          };
        }
        const score = `${c.game.home} ${a.homeScore}, ${c.game.away} ${a.awayScore}`;
        if (a.homeScore === a.awayScore) {
          return c.ifTie === "unlock"
            ? { state: "met", reason: `tie (${score}), and the sealed rule unlocks on a tie`, reports }
            : { state: "not-met", resolved: true, reason: `tie (${score}); the sealed rule keeps it locked until the fail-safe`, reports };
        }
        const teamIsHome = teamKey(c.team) === teamKey(c.game.home);
        const won = teamIsHome ? a.homeScore > a.awayScore : a.awayScore > a.homeScore;
        const result = won ? "win" : "loss";
        return result === c.outcome
          ? { state: "met", reason: `final: ${score}; ${c.team} ${result === "win" ? "won" : "lost"} as sealed`, reports }
          : {
              state: "not-met",
              resolved: true,
              reason: `final: ${score}; ${c.team} ${result === "win" ? "won" : "lost"}, the sealed outcome was a ${c.outcome}; only the fail-safe opens it`,
              reports,
            };
      }
    }
  }
}
