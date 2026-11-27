/** The test/staging hooks used by the e2e stack must be refused in production. */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { QUICKNET } from "@condlock/core";
import { drandChainFromEnv } from "../src/config.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const tsx = path.resolve(here, "../../../node_modules/.bin/tsx");

describe("production guards for test hooks", () => {
  it("the drand chain is pinned to quicknet in production", () => {
    assert.equal(drandChainFromEnv({}), QUICKNET);
    assert.throws(() => drandChainFromEnv({ NODE_ENV: "production", DRAND_CHAIN_FILE: "/nonexistent.json" }), /not allowed in production/);
  });

  for (const [name, env] of [
    ["an extra egress CA", { EGRESS_EXTRA_CA_FILE: "/nonexistent.pem", EGRESS_ROUTES: "x.example=127.0.0.1:1", NSM_ATTEST_COMMAND: "/bin/false" }],
    ["decrypting without attestation", { DEV_NO_ATTESTATION: "1" }],
    ["another drand chain", { DRAND_CHAIN_FILE: "/nonexistent.json", EGRESS_ROUTES: "x.example=127.0.0.1:1", NSM_ATTEST_COMMAND: "/bin/false" }],
  ] as const) {
    it(`the enclave verifier refuses to start with ${name} in production`, () => {
      const r = spawnSync(tsx, ["--conditions=development", path.resolve(here, "../src/verifier/main.ts")], {
        env: { PATH: process.env.PATH ?? "", NODE_ENV: "production", VERIFIER_SOCKET: path.join(here, "never.sock"), ...env },
        encoding: "utf8",
        timeout: 30_000,
      });
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /not allowed in production/);
    });
  }
});
