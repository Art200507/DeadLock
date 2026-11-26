/** Local / self-hosted entry point: `pnpm --filter @condlock/escrow dev`. */
import { defaultProvider } from "@aws-sdk/credential-provider-node";
import { serve } from "@hono/node-server";
import { createApp } from "./app.js";
import { buildFromEnv } from "./config.js";
import { startCredentialRelay } from "./verifier/credential-relay.js";

const env = process.env;
const built = await buildFromEnv();
const app = createApp({ escrow: built.escrow, ...(built.adminToken ? { adminToken: built.adminToken } : {}) });

// On the enclave's parent: deliver AWS credentials (IMDS via the default chain) and sports keys.
if (env.CREDENTIAL_RELAY === "1") {
  if (!built.verifierTarget) throw new Error("CREDENTIAL_RELAY needs VERIFIER_SOCKET or VERIFIER_ADDR");
  startCredentialRelay({
    target: built.verifierTarget,
    ...(env.KMS_PROVIDER === "mock" ? {} : { aws: defaultProvider() }),
    sports: {
      ...(env.APISPORTS_KEY ? { apiSportsKey: env.APISPORTS_KEY } : {}),
      ...(env.THESPORTSDB_KEY ? { theSportsDbKey: env.THESPORTSDB_KEY } : {}),
    },
    onPush: (stored) => console.log(`condlock: delivered ${stored.join(", ")} to the verifier`),
    onError: (err) => console.error(`condlock: credential relay: ${err.message}`),
  });
}

const port = Number(env.PORT ?? 8787);
serve({ fetch: app.fetch, port, hostname: env.HOST ?? "127.0.0.1" }, (info) => {
  console.log(`condlock escrow listening on http://${info.address}:${info.port}`);
});
