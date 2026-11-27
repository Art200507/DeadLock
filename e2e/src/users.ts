/** Test users: a home (device key) and a working folder, driving the real CLI. */
import * as fsp from "node:fs/promises";
import * as path from "node:path";
import * as age from "age-encryption";
import { makeMixedFolder, type Stack } from "./stack.js";

export interface User {
  name: string;
  home: string;
  cwd: string;
  cli(...args: string[]): Promise<{ code: number; stdout: string; stderr: string }>;
  /** Make a mixed folder (photo, PDF, ~2 MiB video, nested note) under cwd. */
  folder(name: string): Promise<string>;
  writeJson(name: string, v: unknown): Promise<string>;
}

export async function newUser(s: Stack, name: string, escrowUrl: string): Promise<User> {
  const home = path.join(s.dir, "users", name, "condlock-home");
  const cwd = path.join(s.dir, "users", name, "work");
  await fsp.mkdir(cwd, { recursive: true });
  const u: User = {
    name,
    home,
    cwd,
    cli: (...args) => s.cli(args, { cwd, home }),
    folder: (n) => makeMixedFolder(path.join(cwd, n), 2 * 1024 * 1024 + 7),
    writeJson: async (n, v) => {
      const p = path.join(cwd, n);
      await fsp.writeFile(p, JSON.stringify(v, null, 2));
      return p;
    },
  };
  const reg = await s.cli(["device", "register", "--escrow", escrowUrl, "--label", name], {
    cwd,
    home,
    env: { CONDLOCK_ADMIN_TOKEN: "e2e-admin-token-not-a-secret" },
  });
  if (reg.code !== 0) throw new Error(`device register failed: ${reg.stdout}${reg.stderr}`);
  return u;
}

export async function guardian() {
  const identity = await age.generateX25519Identity();
  return { identity, recipient: await age.identityToRecipient(identity) };
}

/** An NFL condition (as the CLI's --nfl file) for one mock game. */
export function nflRule(game: { apiSportsId: string; theSportsDbId: string; kickoffAt: Date }, over: Record<string, unknown> = {}) {
  return {
    type: "nfl",
    game: {
      apiSportsId: game.apiSportsId,
      theSportsDbId: game.theSportsDbId,
      home: "Buffalo Bills",
      away: "Miami Dolphins",
      kickoffAt: game.kickoffAt.toISOString(),
    },
    team: "Buffalo Bills",
    outcome: "win",
    ifTie: "stay-locked",
    ifPostponed: "wait",
    ifCancelled: "stay-locked",
    ...over,
  };
}

let gameSeq = 9100;
/** A fresh mock game (unique IDs), not started, kicking off at `kickoffAt`. */
export function newGame(s: Stack, kickoffAt: Date) {
  const n = gameSeq++;
  const g = { apiSportsId: String(n), theSportsDbId: String(2_000_000 + n), kickoffAt };
  s.sports.set({ ...g, home: "Buffalo Bills", away: "Miami Dolphins", apiStatus: "NS", tsdbStatus: "NS", homeScore: null, awayScore: null });
  return {
    ...g,
    score: (apiStatus: string, tsdbStatus: string, home: number | null, away: number | null) =>
      s.sports.update(g.apiSportsId, { apiStatus, tsdbStatus, homeScore: home, awayScore: away }),
  };
}
