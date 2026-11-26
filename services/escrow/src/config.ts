/**
 * Builds the service from environment variables. Secrets come only from the environment
 * (a git-ignored .env locally, the host's secret store in production).
 *
 *   DATABASE_URL         postgres://... (Neon/Supabase). Or ESCROW_DB=pglite:memory | pglite:<dir> for local dev.
 *   KMS_PROVIDER         aws | mock            (mock is refused when NODE_ENV=production)
 *   KMS_KEY_ID           AWS KMS key ARN, key ID or alias (aws only)
 *   AWS_REGION           e.g. us-east-1 (aws only; credentials via the standard AWS chain)
 *   ESCROW_ADMIN_TOKEN   bearer token for POST /devices; unset disables registration over HTTP
 *   VERIFIER_SOCKET      Unix socket of the key-release verifier (bridged to the enclave's vsock), or
 *   VERIFIER_ADDR        host:port of the verifier, or
 *   VERIFIER_INPROCESS=1 run the verifier inside this process (local development; never production)
 */
import { QUICKNET, createDrandClient } from "@condlock/core";
import { Escrow } from "./escrow.js";
import { migrate, pgliteClient, postgresClient, type SqlClient } from "./db.js";
import { AwsKms } from "./keywrap/aws-kms.js";
import { MockKms } from "./keywrap/mock-kms.js";
import { KeyWrapRegistry, type KeyWrapper } from "./keywrap/types.js";
import type { KeyReleaser } from "./verifier/protocol.js";
import { InProcessReleaser, SocketReleaser } from "./verifier/transport.js";
import { KeyReleaseVerifier } from "./verifier/verifier.js";

export interface Built {
  escrow: Escrow;
  db: SqlClient;
  adminToken?: string;
}

export function keyWrapperFromEnv(env: NodeJS.ProcessEnv): KeyWrapper {
  const provider = env.KMS_PROVIDER ?? "aws";
  if (provider === "aws") {
    if (!env.KMS_KEY_ID) throw new Error("KMS_KEY_ID is required when KMS_PROVIDER=aws");
    return new AwsKms({ keyId: env.KMS_KEY_ID, ...(env.AWS_REGION ? { region: env.AWS_REGION } : {}) });
  }
  if (provider === "mock") {
    if (env.NODE_ENV === "production") throw new Error("KMS_PROVIDER=mock is not allowed in production");
    return new MockKms();
  }
  throw new Error(`unknown KMS_PROVIDER ${provider}`);
}

export async function dbFromEnv(env: NodeJS.ProcessEnv): Promise<SqlClient> {
  if (env.DATABASE_URL) return postgresClient(env.DATABASE_URL);
  const spec = env.ESCROW_DB ?? "";
  if (spec === "pglite:memory") return pgliteClient();
  if (spec.startsWith("pglite:")) return pgliteClient(spec.slice("pglite:".length));
  throw new Error("set DATABASE_URL, or ESCROW_DB=pglite:memory for local development");
}

export function releaserFromEnv(env: NodeJS.ProcessEnv, wrapper: KeyWrapper): KeyReleaser {
  if (env.VERIFIER_SOCKET) return new SocketReleaser({ path: env.VERIFIER_SOCKET });
  if (env.VERIFIER_ADDR) {
    const m = /^([^:]+):(\d+)$/.exec(env.VERIFIER_ADDR);
    if (!m) throw new Error("VERIFIER_ADDR must be host:port");
    return new SocketReleaser({ host: m[1]!, port: Number(m[2]) });
  }
  if (env.VERIFIER_INPROCESS === "1") {
    if (env.NODE_ENV === "production") throw new Error("VERIFIER_INPROCESS is not allowed in production");
    return new InProcessReleaser(new KeyReleaseVerifier({ keys: new KeyWrapRegistry(wrapper) }));
  }
  throw new Error("set VERIFIER_SOCKET or VERIFIER_ADDR (or VERIFIER_INPROCESS=1 for local development)");
}

export async function buildFromEnv(env: NodeJS.ProcessEnv = process.env): Promise<Built> {
  const wrapper = keyWrapperFromEnv(env);
  const releaser = releaserFromEnv(env, wrapper);
  const db = await dbFromEnv(env);
  await migrate(db);
  const escrow = new Escrow({ db, keys: new KeyWrapRegistry(wrapper), releaser, drand: createDrandClient(QUICKNET) });
  return { escrow, db, ...(env.ESCROW_ADMIN_TOKEN ? { adminToken: env.ESCROW_ADMIN_TOKEN } : {}) };
}
