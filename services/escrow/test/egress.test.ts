/**
 * Egress and credential delivery. TLS terminates inside the verifier; the forwarders (standing in
 * for socat and the parent's vsock-proxy) see only ciphertext and can't impersonate a provider.
 * The parent delivers AWS credentials and API keys over the verifier channel, and the AWS SDK
 * inside the verifier uses them, over the same egress path, to reach KMS.
 */
import assert from "node:assert/strict";
import * as fsp from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { after, before, describe, it } from "node:test";
import { NodeHttpHandler } from "@smithy/node-http-handler";
import { EgressRefusedError, RoutedDialer, parseRoutes } from "../src/egress/dialer.js";
import { startForwarder } from "../src/egress/forwarder.js";
import { EgressHttps } from "../src/egress/https.js";
import { AwsKms } from "../src/keywrap/aws-kms.js";
import { KeyServiceError, KeyWrapRegistry } from "../src/keywrap/types.js";
import { startCredentialRelay } from "../src/verifier/credential-relay.js";
import { SecretStore } from "../src/verifier/secrets.js";
import { pushSecrets, serveVerifier } from "../src/verifier/transport.js";
import { KeyReleaseVerifier } from "../src/verifier/verifier.js";
import {
  API_SPORTS_HOST,
  KMS_HOST,
  TEST_APISPORTS_KEY,
  THESPORTSDB_HOST,
  egressRig,
  type EgressRig,
} from "./helpers/sports.js";
import { serverCert, startHttps, testCa } from "./helpers/tls.js";
import { randomBytes } from "node:crypto";

describe("egress: TLS inside the verifier over forwarded bytes", () => {
  let rig: EgressRig;
  before(async () => {
    rig = await egressRig();
    rig.sports.set({
      apiSportsId: "7803",
      theSportsDbId: "1942349",
      home: "Kansas City Chiefs",
      away: "San Francisco 49ers",
      apiStatus: "AOT",
      tsdbStatus: "FT",
      homeScore: 25,
      awayScore: 22,
    });
  });
  after(() => rig.close());

  it("fetches through the allowlisted route, and the relay sees only ciphertext", async () => {
    rig.seen.up.length = rig.seen.down.length = 0;
    const res = await rig.http.getJson(`https://${API_SPORTS_HOST}/games?id=7803`, { "x-apisports-key": TEST_APISPORTS_KEY });
    assert.equal(res.status, 200);
    assert.equal((res.json as any).response[0].teams.home.name, "Kansas City Chiefs");
    const up = Buffer.concat(rig.seen.up).toString("latin1");
    const down = Buffer.concat(rig.seen.down).toString("latin1");
    assert.ok(up.length > 0 && down.length > 0, "bytes did cross the relay");
    assert.ok(!up.includes(TEST_APISPORTS_KEY) && !up.includes("/games?id="), "the parent can't read the request");
    assert.ok(!down.includes("Kansas City Chiefs"), "the parent can't read the response");
  });

  it("refuses hosts that aren't on the allowlist, and non-https URLs", async () => {
    await assert.rejects(rig.http.getJson("https://example.com/"), EgressRefusedError);
    await assert.rejects(rig.http.getJson(`http://${API_SPORTS_HOST}/games?id=1`), /only https/);
  });

  it("a parent that answers with its own certificate (other CA) is rejected", async () => {
    const evilCa = await testCa("Evil Parent CA");
    const evil = await startHttps(await serverCert(evilCa, [API_SPORTS_HOST]), () => ({
      json: { errors: [], response: [{ fake: "a forged final score" }] },
    }));
    const fwd = await startForwarder({ host: "127.0.0.1", port: evil.port });
    try {
      const http = new EgressHttps({ dialer: new RoutedDialer({ [`${API_SPORTS_HOST}:443`]: { host: "127.0.0.1", port: fwd.port } }), ca: [rig.ca.certPem] });
      await assert.rejects(http.getJson(`https://${API_SPORTS_HOST}/games?id=7803`), (e: NodeJS.ErrnoException) =>
        /certificate|self.signed|unable to verify/i.test(`${e.code} ${e.message}`),
      );
    } finally {
      await fwd.close();
      await evil.close();
    }
  });

  it("a parent that routes one host to another (valid cert, wrong name) is rejected", async () => {
    const other = await startHttps(await serverCert(rig.ca, [THESPORTSDB_HOST]), () => ({ json: {} }));
    const fwd = await startForwarder({ host: "127.0.0.1", port: other.port });
    try {
      const http = new EgressHttps({ dialer: new RoutedDialer({ [`${API_SPORTS_HOST}:443`]: { host: "127.0.0.1", port: fwd.port } }), ca: [rig.ca.certPem] });
      await assert.rejects(http.getJson(`https://${API_SPORTS_HOST}/games?id=7803`), (e: NodeJS.ErrnoException) =>
        /altname|hostname|ERR_TLS_CERT_ALTNAME_INVALID/i.test(`${e.code} ${e.message}`),
      );
    } finally {
      await fwd.close();
      await other.close();
    }
  });

  it("by default trusts only Node's bundled roots, so the test CA is not trusted", async () => {
    const http = new EgressHttps({ dialer: new RoutedDialer(rig.routes) });
    await assert.rejects(http.getJson(`https://${API_SPORTS_HOST}/games?id=7803`), (e: NodeJS.ErrnoException) =>
      /certificate|unable to verify|self.signed/i.test(`${e.code} ${e.message}`),
    );
  });

  it("parses EGRESS_ROUTES", () => {
    assert.deepEqual(parseRoutes("kms.us-east-1.amazonaws.com=127.0.0.1:8000, www.thesportsdb.com:443=/run/tsdb.sock"), {
      "kms.us-east-1.amazonaws.com:443": { host: "127.0.0.1", port: 8000 },
      "www.thesportsdb.com:443": { path: "/run/tsdb.sock" },
    });
    assert.throws(() => parseRoutes("nonsense"), /bad EGRESS_ROUTES/);
  });
});

describe("credential delivery into the verifier (closes the milestone 4 gap)", () => {
  let rig: EgressRig;
  let dir: string;
  let socketPath: string;
  let server: import("node:net").Server;
  let secrets: SecretStore;
  let kms: AwsKms;
  const ctx = { vaultId: randomBytes(16).toString("hex"), seal: randomBytes(32).toString("hex") };
  const wrapped = { scheme: "aws-kms/v1", keyId: "arn:aws:kms:us-east-1:000000000000:key/test", ciphertext: Buffer.from("opaque").toString("base64") };

  before(async () => {
    rig = await egressRig();
    dir = await fsp.mkdtemp(path.join(tmpdir(), "condlock-creds-"));
    socketPath = path.join(dir, "verifier.sock");
    secrets = new SecretStore();
    // The verifier's KMS client: credentials from the store, HTTPS over the egress path.
    kms = new AwsKms({
      keyId: "unwrap-only",
      region: "us-east-1",
      credentials: secrets.awsCredentials,
      requestHandler: new NodeHttpHandler({ httpsAgent: rig.http.agent }),
    });
    server = await serveVerifier(new KeyReleaseVerifier({ keys: new KeyWrapRegistry(kms), secrets }), { path: socketPath });
  });
  after(async () => {
    await new Promise<void>((r) => server.close(() => r()));
    await rig.close();
    await fsp.rm(dir, { recursive: true, force: true });
  });

  it("without delivered credentials, the verifier can't call KMS", async () => {
    await assert.rejects(kms.unwrap(wrapped, ctx), KeyServiceError);
    assert.equal(rig.sports.kmsRequests.length, 0);
  });

  it("the parent pushes credentials over the verifier socket; KMS calls go out signed with them, via egress", async () => {
    const res = await pushSecrets({ path: socketPath }, {
      v: 1,
      op: "secrets",
      aws: { accessKeyId: "TEST-ACCESS-KEY-DELIVERED", secretAccessKey: "test-secret-not-real", sessionToken: "test-session-token", expiration: new Date(Date.now() + 3_600_000).toISOString() },
      sports: { apiSportsKey: "k1", theSportsDbKey: "k2" },
    });
    assert.deepEqual(res, { v: 1, ok: true, op: "secrets", stored: ["aws", "sports"] });
    assert.equal(secrets.apiSportsKey(), "k1");

    const out = await kms.unwrap(wrapped, ctx);
    assert.deepEqual(Buffer.from(out), rig.sports.kmsPlaintext);
    const req = rig.sports.kmsRequests.at(-1)!;
    assert.match(String(req.headers.authorization), /Credential=TEST-ACCESS-KEY-DELIVERED\//, "SigV4 with the delivered key");
    assert.equal(req.headers["x-amz-security-token"], "test-session-token");
    assert.deepEqual(JSON.parse(req.body).EncryptionContext, { app: "condition-lock", vaultId: ctx.vaultId, seal: ctx.seal });
    const relayed = Buffer.concat(rig.seen.up).toString("latin1");
    assert.ok(!relayed.includes("TEST-ACCESS-KEY-DELIVERED"), "the relayed KMS traffic is TLS ciphertext");
  });

  it("refuses expired credentials and malformed deliveries", async () => {
    const store = new SecretStore();
    store.accept({ v: 1, op: "secrets", aws: { accessKeyId: "TEST-ACCESS-KEY-OLD", secretAccessKey: "x", expiration: new Date(Date.now() - 1000).toISOString() } });
    await assert.rejects(store.awsCredentials(), /expired/);
    assert.equal(store.accept({ v: 1, op: "secrets", aws: { accessKeyId: 5 } }).ok, false);
    assert.equal(store.accept({ v: 1, op: "nope" }).ok, false);
    const noSecrets = new KeyReleaseVerifier({ keys: new KeyWrapRegistry(kms) });
    assert.equal((await noSecrets.handle({ v: 1, op: "secrets", sports: {} })).ok, false);
  });

  it("the relay pushes on start and schedules a refresh before the credentials expire", async () => {
    const pushed: string[][] = [];
    const expiration = new Date(Date.now() + 8 * 60_000);
    const relay = startCredentialRelay({
      target: { path: socketPath },
      aws: async () => ({ accessKeyId: "TEST-ACCESS-KEY-RELAYED", secretAccessKey: "s", sessionToken: "t", expiration }),
      sports: { apiSportsKey: "relayed-key" },
      onPush: (stored) => pushed.push(stored),
    });
    try {
      const next = await relay.pushNow();
      assert.ok(next <= 3 * 60_000 + 1000 && next >= 30_000, `refresh ~5 min before expiry, got ${next}ms`);
      assert.ok(pushed.length >= 1);
      assert.equal((await secrets.awsCredentials()).accessKeyId, "TEST-ACCESS-KEY-RELAYED");
      assert.equal(secrets.apiSportsKey(), "relayed-key");
    } finally {
      relay.stop();
    }
  });
});
