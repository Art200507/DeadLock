/**
 * Mock API-Sports and TheSportsDB, served over real TLS (test CA) and reached through byte
 * forwarders that stand in for the enclave's socat and the parent's vsock-proxy. Responses use
 * the providers' real field names (TheSportsDB's checked against its public API).
 */
import type { IncomingMessage } from "node:http";
import { RoutedDialer, type LocalTarget } from "../../src/egress/dialer.js";
import { startForwarder, type Forwarder } from "../../src/egress/forwarder.js";
import { EgressHttps } from "../../src/egress/https.js";
import { serverCert, startHttps, testCa, type TestCa, type TestHttpsServer } from "./tls.js";

export const API_SPORTS_HOST = "v1.american-football.api-sports.io";
export const THESPORTSDB_HOST = "www.thesportsdb.com";
export const KMS_HOST = "kms.us-east-1.amazonaws.com";
/** Test-only placeholder keys; never real. */
export const TEST_APISPORTS_KEY = "test-apisports-key-not-real";
export const TEST_THESPORTSDB_KEY = "test-tsdb-key-not-real";

export interface MockGame {
  apiSportsId: string;
  theSportsDbId: string;
  home: string;
  away: string;
  /** API-Sports status.short: NS, Q1..Q4, HT, OT, FT, AOT, PST, CANC. */
  apiStatus: string;
  /** TheSportsDB strStatus: "NS", "FT", "AOT", "Postponed", "Cancelled", ... */
  tsdbStatus: string;
  homeScore: number | null;
  awayScore: number | null;
  /** Override one source's numbers to simulate disagreement. */
  tsdbHomeScore?: number | null | undefined;
  tsdbAwayScore?: number | null | undefined;
  tsdbLinksApiSportsId?: string | null | undefined;
}

export class MockSports {
  games = new Map<string, MockGame>();
  down = { apiSports: false, theSportsDb: false };
  requests: { host: string; url: string; headers: IncomingMessage["headers"] }[] = [];
  kmsRequests: { headers: IncomingMessage["headers"]; body: string }[] = [];
  kmsPlaintext = Buffer.alloc(32, 7);

  set(g: MockGame) {
    this.games.set(g.apiSportsId, g);
    this.games.set(`tsdb:${g.theSportsDbId}`, g);
  }

  update(apiSportsId: string, patch: Partial<MockGame>) {
    const g = this.games.get(apiSportsId);
    if (!g) throw new Error("no such mock game");
    this.set({ ...g, ...patch });
  }

  handle(req: IncomingMessage, body: string): { status?: number; json: unknown; headers?: Record<string, string> } {
    const host = String(req.headers.host ?? "").replace(/:\d+$/, "");
    const url = new URL(req.url ?? "/", `https://${host}`);
    this.requests.push({ host, url: req.url ?? "", headers: req.headers });
    if (host === API_SPORTS_HOST) {
      if (this.down.apiSports) return { status: 503, json: { message: "down" } };
      if (req.headers["x-apisports-key"] !== TEST_APISPORTS_KEY) {
        return { json: { get: "games", errors: { token: "Error/Missing application key." }, results: 0, response: [] } };
      }
      const g = this.games.get(url.searchParams.get("id") ?? "");
      if (!g) return { json: { get: "games", errors: [], results: 0, response: [] } };
      return {
        json: {
          get: "games",
          parameters: { id: g.apiSportsId },
          errors: [],
          results: 1,
          response: [
            {
              game: { id: Number(g.apiSportsId), status: { short: g.apiStatus, long: g.apiStatus, timer: null } },
              teams: { home: { id: 1, name: g.home }, away: { id: 2, name: g.away } },
              scores: { home: { total: g.homeScore }, away: { total: g.awayScore } },
            },
          ],
        },
      };
    }
    if (host === THESPORTSDB_HOST) {
      if (this.down.theSportsDb) return { status: 502, json: { message: "bad gateway" } };
      const m = /^\/api\/v1\/json\/([^/]+)\/lookupevent\.php$/.exec(url.pathname);
      if (!m || m[1] !== TEST_THESPORTSDB_KEY) return { status: 401, json: { message: "bad key" } };
      const g = this.games.get(`tsdb:${url.searchParams.get("id")}`);
      if (!g) return { json: { events: null } };
      const hs = g.tsdbHomeScore !== undefined ? g.tsdbHomeScore : g.homeScore;
      const as = g.tsdbAwayScore !== undefined ? g.tsdbAwayScore : g.awayScore;
      const link = g.tsdbLinksApiSportsId === undefined ? g.apiSportsId : g.tsdbLinksApiSportsId;
      return {
        json: {
          events: [
            {
              idEvent: g.theSportsDbId,
              idAPIfootball: link,
              strHomeTeam: g.home,
              strAwayTeam: g.away,
              intHomeScore: hs === null ? null : String(hs),
              intAwayScore: as === null ? null : String(as),
              strStatus: g.tsdbStatus,
              strPostponed: g.tsdbStatus === "Postponed" ? "yes" : "no",
              strLeague: "NFL",
            },
          ],
        },
      };
    }
    if (host === KMS_HOST) {
      this.kmsRequests.push({ headers: req.headers, body });
      const target = String(req.headers["x-amz-target"] ?? "");
      if (target !== "TrentService.Decrypt") return { status: 400, json: { __type: "UnsupportedOperationException" } };
      const keyId = (JSON.parse(body) as { KeyId?: string }).KeyId ?? "arn:aws:kms:us-east-1:000000000000:key/test";
      return {
        headers: { "content-type": "application/x-amz-json-1.1" },
        json: { KeyId: keyId, Plaintext: this.kmsPlaintext.toString("base64"), EncryptionAlgorithm: "SYMMETRIC_DEFAULT" },
      };
    }
    return { status: 404, json: { message: `no mock for ${host}` } };
  }
}

/**
 * The whole egress path for tests: mock HTTPS servers (one cert for all three hostnames, from a
 * test CA), one forwarder per host (the vsock-proxy stand-in), a RoutedDialer allowlist, and an
 * EgressHttps that trusts only the test CA.
 */
export interface EgressRig {
  ca: TestCa;
  sports: MockSports;
  server: TestHttpsServer;
  forwarders: Record<string, Forwarder>;
  routes: Record<string, LocalTarget>;
  http: EgressHttps;
  /** Bytes that crossed the forwarders (what the parent can see). */
  seen: { up: Buffer[]; down: Buffer[] };
  close(): Promise<void>;
}

export async function egressRig(): Promise<EgressRig> {
  const ca = await testCa();
  const sports = new MockSports();
  const server = await startHttps(await serverCert(ca, [API_SPORTS_HOST, THESPORTSDB_HOST, KMS_HOST]), (req, body) => sports.handle(req, body));
  const seen = { up: [] as Buffer[], down: [] as Buffer[] };
  const forwarders: Record<string, Forwarder> = {};
  const routes: Record<string, LocalTarget> = {};
  for (const host of [API_SPORTS_HOST, THESPORTSDB_HOST, KMS_HOST]) {
    forwarders[host] = await startForwarder({ host: "127.0.0.1", port: server.port }, { onBytes: (dir, d) => seen[dir].push(d) });
    routes[`${host}:443`] = { host: "127.0.0.1", port: forwarders[host]!.port };
  }
  const http = new EgressHttps({ dialer: new RoutedDialer(routes), ca: [ca.certPem] });
  return {
    ca,
    sports,
    server,
    forwarders,
    routes,
    http,
    seen,
    async close() {
      for (const f of Object.values(forwarders)) await f.close();
      await server.close();
    },
  };
}
