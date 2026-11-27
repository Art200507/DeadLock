/**
 * Apply database migrations, as the database owner (not the service role, which can't change
 * the schema): `pnpm --filter @condlock/escrow migrate` with DATABASE_URL set to the owner's URL.
 */
import { dbFromEnv } from "./config.js";
import { migrate } from "./db.js";

const db = await dbFromEnv(process.env);
try {
  const ran = await migrate(db);
  console.log(ran.length ? `applied: ${ran.join(", ")}` : "already up to date");
} finally {
  await db.close();
}
