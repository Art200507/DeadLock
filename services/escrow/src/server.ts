/** Local / self-hosted entry point: `pnpm --filter @condlock/escrow dev`. */
import { serve } from "@hono/node-server";
import { createApp } from "./app.js";
import { buildFromEnv } from "./config.js";

const built = await buildFromEnv();
const app = createApp({ escrow: built.escrow, ...(built.adminToken ? { adminToken: built.adminToken } : {}) });
const port = Number(process.env.PORT ?? 8787);
serve({ fetch: app.fetch, port, hostname: process.env.HOST ?? "127.0.0.1" }, (info) => {
  console.log(`condlock escrow listening on http://${info.address}:${info.port}`);
});
