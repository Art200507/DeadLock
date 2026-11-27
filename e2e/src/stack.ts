/**
 * The whole system, locally, wired the way it is deployed (docs/DEPLOY.md):
 *
 *   condlock CLI (subprocess) ──https-ish──► escrow API (process, src/server.ts) ─► Postgres
 *                                                │  Unix socket (vsock stand-in)      (PGlite behind a real
 *                                                ▼                                    Postgres wire socket)
 *                                      enclave verifier (process, src/verifier/main.ts)
 *                                        │ egress allowlist → forwarders (vsock-proxy stand-ins) → TLS:
 *                                        ├─► KMS (mock, real AWS JSON protocol, PCR0 key policies)
 *                                        ├─► API-Sports (mock)   └─► TheSportsDB (mock)
 *   drand relay (mock chain, real HTTP API) ◄── CLI, API
 *
 * Everything outside the two processes (drand, KMS, sports APIs, Postgres) runs in this test
 * process so tests can steer it: publish drand rounds, change scores, take a provider down. All
 * files live in one temp directory; HOME points there too, so nothing reads ~/.aws or ~/.condlock.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import * as fsp from "node:fs/promises";
import * as http from "node:http";
import * as net from "node:net";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { PGlite } from "@electric-sql/pglite";
import { PGLiteSocketServer } from "@electric-sql/pglite-socket";
import { roundForTime, timeOfRound } from "@condlock/core";
import { MockKmsService } from "@condlock/escrow";
import { startForwarder, type Forwarder } from "../../services/escrow/src/egress/forwarder.js";
import pg from "pg";
import { MockDrand } from "../../packages/core/test/helpers/mock-drand.js";
import {
  API_SPORTS_HOST,
  KMS_HOST,
  MockSports,
  TEST_APISPORTS_KEY,
  TEST_THESPORTSDB_KEY,
  THESPORTSDB_HOST,
} from "../../services/escrow/test/helpers/sports.js";
import { serverCert, startHttps, testCa, type TestHttpsServer } from "../../services/escrow/test/helpers/tls.js";
import { MockKmsHttp, type KmsKey } from "./mock-kms-http.js";

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const TSX = path.join(ROOT, "node_modules/.bin/tsx");
const ATTEST = path.join(ROOT, "e2e/bin/mock-nsm-attest.mjs");
/** The approved enclave image measurement (what the key policies pin). */
export const APPROVED_PCR0 = "e2".repeat(48);
/** Not secrets: only valid against this test stack's in-memory services. */
export const ADMIN_TOKEN = "e2e-admin-token-not-a-secret";
export const PARENT_ROLE_KEY_ID = "E2E-PARENT-ROLE-ACCESS-KEY";
export const KEY_A = "arn:aws:kms:us-east-1:000000000000:key/e2e-escrow-key";
export const KEY_B = "arn:aws:kms:us-east-1:111111111111:key/e2e-second-provider-key";

export interface Proc {
  name: string;
  child: ChildProcess;
  output: string[];
  stop(): Promise<void>;
}

export interface CliResult {
  code: number;
  stdout: string;
  stderr: string;
}

async function freePort(): Promise<number> {
  const s = net.createServer();
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  const port = (s.address() as net.AddressInfo).port;
  await new Promise<void>((r) => s.close(() => r()));
  return port;
}

function startProc(name: string, script: string, env: Record<string, string>, ready: RegExp): Promise<Proc> {
  const child = spawn(TSX, ["--conditions=development", script], { cwd: ROOT, env, stdio: ["ignore", "pipe", "pipe"] });
  const output: string[] = [];
  const proc: Proc = {
    name,
    child,
    output,
    stop: () =>
      new Promise<void>((resolve) => {
        if (child.exitCode !== null) return resolve();
        child.once("exit", () => resolve());
        child.kill("SIGTERM");
      }),
  };
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${name} didn't start:\n${output.join("")}`)), 30_000);
    const onData = (d: Buffer) => {
      output.push(d.toString());
      if (ready.test(output.join(""))) {
        clearTimeout(timer);
        resolve(proc);
      }
    };
    child.stdout!.on("data", onData);
    child.stderr!.on("data", onData);
    child.once("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`${name} exited with ${code}:\n${output.join("")}`));
    });
  });
}

export interface Stack {
  dir: string;
  drand: MockDrand;
  /** Publish every drand round up to this time. drand never runs backwards. */
  drandAt(t: Date | number): void;
  drandNow(): Date;
  sports: MockSports;
  kms: MockKmsHttp;
  keyA: KmsKey;
  keyB: KmsKey;
  /** A superuser connection to the escrow's database: the "admin with database access" for cheat tests. */
  admin: pg.Client;
  escrowUrl: string;
  splitUrl: string;
  verifierSocket: string;
  /** The mock KMS endpoint and the CA that signs its certificate (for "call KMS directly" attempts). */
  kmsEndpoint: string;
  caPem: string;
  procs: Proc[];
  forwarders: Record<string, Forwarder>;
  /** Base environment for the CLI (a fresh CONDLOCK_HOME per user). */
  cliEnv(home: string, extra?: Record<string, string>): Record<string, string>;
  cli(args: string[], o: { cwd: string; home: string; env?: Record<string, string> }): Promise<CliResult>;
  /** Start another verifier process (e.g. a non-approved image) on its own socket. */
  startVerifier(o: { pcr0: string; name: string }): Promise<{ proc: Proc; socket: string }>;
  /** Environment shared by both deployed processes (paths, CA, drand). */
  baseEnv(): Record<string, string>;
  stop(): Promise<void>;
}

export async function startStack(): Promise<Stack> {
  const dir = await fsp.mkdtemp(path.join(tmpdir(), "condlock-e2e-"));
  const homeDir = path.join(dir, "home");
  await fsp.mkdir(homeDir);
  const cleanups: (() => Promise<void>)[] = [];

  // --- drand: a private chain aligned with the real clock, served over drand's HTTP API.
  const drand = new MockDrand(Math.floor(Date.now() / 1000) - 300, 3);
  const chainFile = path.join(dir, "drand-chain.json");
  await fsp.writeFile(chainFile, JSON.stringify(drand.info));
  const drandAt = (t: Date | number) => drand.publish(roundForTime(new Date(t), drand.chainParams));
  drandAt(Date.now());
  const drandServer = http.createServer((req, res) => {
    const m = new RegExp(`^/${drand.info.hash}/(info|public/latest|public/(\\d+))$`).exec(req.url ?? "");
    const send = (status: number, body: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (!m) return send(404, { error: "not found" });
    if (m[1] === "info") return send(200, drand.info);
    const round = m[2] ? Number(m[2]) : drand.latestRound;
    if (round > drand.latestRound || round < 1) return send(425, { error: "round not yet available" });
    return send(200, drand.beacon(round));
  });
  await new Promise<void>((r) => drandServer.listen(0, "127.0.0.1", r));
  const drandUrl = `http://127.0.0.1:${(drandServer.address() as net.AddressInfo).port}`;
  cleanups.push(() => new Promise((r) => drandServer.close(() => r())));

  // --- TLS: a throwaway CA for the mock KMS and sports endpoints.
  const ca = await testCa("Condition Lock e2e CA");
  const caFile = path.join(dir, "e2e-ca.pem");
  await fsp.writeFile(caFile, ca.certPem);

  // --- KMS: two keys with the production policy shape (Decrypt only for the approved PCR0).
  const nitroRoot = generateKeyPairSync("ed25519");
  const rootKeyFile = path.join(dir, "mock-nitro-root.pem");
  await fsp.writeFile(rootKeyFile, nitroRoot.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  const kms = new MockKmsHttp();
  const policy = { policy: { requireAttestedPcr0: APPROVED_PCR0 }, attestationRoot: nitroRoot.publicKey };
  const keyA = kms.add(KEY_A, new MockKmsService({ keyId: KEY_A, ...policy }));
  const keyB = kms.add(KEY_B, new MockKmsService({ keyId: KEY_B, ...policy }));

  // --- One HTTPS server answering as KMS, API-Sports and TheSportsDB (by Host header).
  const sports = new MockSports();
  const servers: TestHttpsServer[] = [];
  const cert = await serverCert(ca, [KMS_HOST, API_SPORTS_HOST, THESPORTSDB_HOST], ["127.0.0.1"]);
  const world = await startHttps(cert, (req, body) => {
    const host = String(req.headers.host ?? "").replace(/:\d+$/, "");
    if (host === KMS_HOST || host === "127.0.0.1") return kms.handle(req, body);
    return sports.handle(req, body);
  });
  servers.push(world);
  cleanups.push(() => world.close());

  // --- The parent's vsock-proxy instances: one forwarder per allowlisted host.
  const forwarders: Record<string, Forwarder> = {};
  const routes: string[] = [];
  for (const host of [KMS_HOST, API_SPORTS_HOST, THESPORTSDB_HOST]) {
    forwarders[host] = await startForwarder({ host: "127.0.0.1", port: world.port });
    routes.push(`${host}=127.0.0.1:${forwarders[host]!.port}`);
  }
  cleanups.push(async () => {
    for (const f of Object.values(forwarders)) await f.close();
  });

  // --- Postgres: PGlite behind a real Postgres wire-protocol socket.
  const pglite = await PGlite.create();
  const pgPort = await freePort();
  const pgServer = new PGLiteSocketServer({ db: pglite, port: pgPort, host: "127.0.0.1", maxConnections: 16 });
  await pgServer.start();
  const databaseUrl = `postgres://postgres:postgres@127.0.0.1:${pgPort}/postgres`;
  cleanups.push(async () => {
    await pgServer.stop();
    await pglite.close();
  });

  const baseEnv = (): Record<string, string> => ({
    PATH: process.env.PATH ?? "",
    HOME: homeDir,
    NODE_ENV: "test",
    AWS_CONFIG_FILE: path.join(dir, "no-aws-config"),
    AWS_SHARED_CREDENTIALS_FILE: path.join(dir, "no-aws-credentials"),
    AWS_EC2_METADATA_DISABLED: "true",
    AWS_REGION: "us-east-1",
    DRAND_CHAIN_FILE: chainFile,
  });

  const procs: Proc[] = [];
  const startVerifier = async (o: { pcr0: string; name: string }) => {
    const socket = path.join(dir, `${o.name}.sock`);
    const proc = await startProc(
      o.name,
      "services/escrow/src/verifier/main.ts",
      {
        ...baseEnv(),
        VERIFIER_SOCKET: socket,
        EGRESS_ROUTES: routes.join(","),
        EGRESS_EXTRA_CA_FILE: caFile,
        NSM_ATTEST_COMMAND: ATTEST,
        MOCK_NSM_PCR0: o.pcr0,
        MOCK_NSM_ROOT_KEY: rootKeyFile,
        SECOND_PROVIDER: "aws",
      },
      /verifier listening/,
    );
    procs.push(proc);
    return { proc, socket };
  };

  const { socket: verifierSocket } = await startVerifier({ pcr0: APPROVED_PCR0, name: "verifier" });

  const startApi = async (name: string, extra: Record<string, string>) => {
    const port = await freePort();
    const proc = await startProc(
      name,
      "services/escrow/src/server.ts",
      {
        ...baseEnv(),
        PORT: String(port),
        HOST: "127.0.0.1",
        DATABASE_URL: databaseUrl,
        DATABASE_POOL_MAX: "4",
        KMS_PROVIDER: "aws",
        KMS_KEY_ID: KEY_A,
        KMS_ENDPOINT: `https://127.0.0.1:${world.port}`,
        NODE_EXTRA_CA_CERTS: caFile,
        // The parent instance's role credentials (fake): relayed into the verifier.
        AWS_ACCESS_KEY_ID: PARENT_ROLE_KEY_ID,
        AWS_SECRET_ACCESS_KEY: "e2e-not-a-secret",
        AWS_SESSION_TOKEN: "e2e-session-token",
        VERIFIER_SOCKET: verifierSocket,
        CREDENTIAL_RELAY: "1",
        APISPORTS_KEY: TEST_APISPORTS_KEY,
        THESPORTSDB_KEY: TEST_THESPORTSDB_KEY,
        ESCROW_ADMIN_TOKEN: ADMIN_TOKEN,
        DRAND_URL: drandUrl,
        ...extra,
      },
      /escrow listening on/,
    );
    procs.push(proc);
    return `http://127.0.0.1:${port}`;
  };
  // Sequentially: the first one runs the migrations.
  const escrowUrl = await startApi("escrow", {});
  const splitUrl = await startApi("escrow-2of3", { KEY_SPLIT: "2of3", SECOND_PROVIDER: "aws", SECOND_KMS_KEY_ID: KEY_B });

  const admin = new pg.Client({ connectionString: databaseUrl });
  await admin.connect();

  const cliEnv = (home: string, extra: Record<string, string> = {}) => ({
    PATH: process.env.PATH ?? "",
    HOME: homeDir,
    CONDLOCK_HOME: home,
    CONDLOCK_DRAND_URL: drandUrl,
    CONDLOCK_DRAND_CHAIN_FILE: chainFile,
    ...extra,
  });

  const cli: Stack["cli"] = (args, o) =>
    new Promise((resolve) => {
      const child = spawn(TSX, ["--conditions=development", path.join(ROOT, "packages/cli/src/index.ts"), ...args], {
        cwd: o.cwd,
        env: { ...cliEnv(o.home), ...(o.env ?? {}) },
        stdio: ["ignore", "pipe", "pipe"],
      });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
      child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
      child.on("close", (code) => resolve({ code: code ?? -1, stdout, stderr }));
    });

  return {
    dir,
    drand,
    drandAt,
    drandNow: () => timeOfRound(drand.latestRound, drand.chainParams),
    sports,
    kms,
    keyA,
    keyB,
    admin,
    escrowUrl,
    splitUrl,
    verifierSocket,
    kmsEndpoint: `https://127.0.0.1:${world.port}`,
    caPem: ca.certPem,
    procs,
    forwarders,
    cliEnv,
    cli,
    startVerifier,
    baseEnv,
    async stop() {
      await admin.end().catch(() => {});
      for (const p of procs.reverse()) await p.stop();
      for (const c of cleanups.reverse()) await c().catch(() => {});
      await fsp.rm(dir, { recursive: true, force: true });
    },
  };
}

/** A folder of mixed files (photo, PDF, video-sized blob, nested note) and its hashes. */
export { makeMixedFolder, hashTree } from "../../packages/cli/test/helpers/fixtures.js";
export const randomHex = (n: number) => randomBytes(n).toString("hex");
