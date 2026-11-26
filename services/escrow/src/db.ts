/**
 * A minimal SQL interface that both node-postgres (production: Neon, Supabase) and PGlite
 * (tests, local dev: real Postgres compiled to WASM, in-process) satisfy. All SQL in the
 * service goes through this, so the same queries and migrations run on both.
 */
import * as fsp from "node:fs/promises";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

export interface SqlClient {
  query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<{ rows: T[] }>;
  /** Run a multi-statement script (migrations). */
  exec(sql: string): Promise<void>;
  close(): Promise<void>;
}

/** In-process Postgres via PGlite. `dataDir` omitted = in memory. */
export async function pgliteClient(dataDir?: string): Promise<SqlClient> {
  const { PGlite } = await import("@electric-sql/pglite");
  const db = dataDir ? await PGlite.create(dataDir) : await PGlite.create();
  return {
    query: async <T>(sql: string, params: unknown[] = []) => ({ rows: (await db.query<T>(sql, params)).rows }),
    exec: async (sql) => {
      await db.exec(sql);
    },
    close: () => db.close(),
  };
}

/** A real Postgres server via node-postgres, e.g. a Neon or Supabase DATABASE_URL. */
export async function postgresClient(connectionString: string): Promise<SqlClient> {
  const { default: pg } = await import("pg");
  const pool = new pg.Pool({ connectionString, max: 5 });
  return {
    query: async <T>(sql: string, params: unknown[] = []) => ({
      rows: (await pool.query(sql, params)).rows as T[],
    }),
    exec: async (sql) => {
      await pool.query(sql);
    },
    close: () => pool.end(),
  };
}

export const DEFAULT_MIGRATIONS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../db/migrations",
);

/** Apply every not-yet-applied `NNN_name.sql` in order, each in its own transaction. */
export async function migrate(db: SqlClient, dir: string = DEFAULT_MIGRATIONS_DIR): Promise<string[]> {
  await db.exec(
    "create table if not exists schema_migrations (name text primary key, applied_at timestamptz not null default now())",
  );
  const applied = new Set(
    (await db.query<{ name: string }>("select name from schema_migrations")).rows.map((r) => r.name),
  );
  const files = (await fsp.readdir(dir)).filter((f) => /^\d{3}_[a-z0-9_]+\.sql$/.test(f)).sort();
  const ran: string[] = [];
  for (const f of files) {
    if (applied.has(f)) continue;
    const sql = await fsp.readFile(path.join(dir, f), "utf8");
    await db.exec(`begin;\n${sql}\ninsert into schema_migrations (name) values ('${f}');\ncommit;`);
    ran.push(f);
  }
  return ran;
}
