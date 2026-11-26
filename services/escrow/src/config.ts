/**
 * Builds the service from environment variables. Secrets come only from the environment
 * (a git-ignored .env locally, the host's secret store in production).
 *
 *   DATABASE_URL         postgres://... (Neon/Supabase). Or ESCROW_DB=pglite:memory | pglite:<dir> for local dev.
 *   KMS_PROVIDER         aws | mock            (mock is refused when NODE_ENV=production)
 *   KMS_KEY_ID           AWS KMS key ARN, key ID or alias (aws only)
 *   AWS_REGION           e.g. us-east-1 (aws only; credentials via the standard AWS chain)
 *   KEY_SPLIT            "2of3" to split new keys: KMS share + second provider + guardian (needs SECOND_*)
 *   SECOND_PROVIDER      aws | mock            the second share holder (aws = a KMS key in another account)
 *   SECOND_KMS_KEY_ID    that key's ARN (SECOND_PROVIDER=aws)
 *   ESCROW_ADMIN_TOKEN   bearer token for POST /devices; unset disables registration over HTTP
 *   VERIFIER_SOCKET      Unix socket of the key-release verifier (bridged to the enclave's vsock), or
 *   VERIFIER_ADDR        host:port of the verifier, or
 *   VERIFIER_INPROCESS=1 run the verifier inside this process (local development; never production)
 *   CREDENTIAL_RELAY=1   push AWS credentials (default chain/IMDS) and the sports keys to the verifier
 *   APISPORTS_KEY, THESPORTSDB_KEY   sports API keys, relayed to the verifier (never used by the API)
 */
import { QUICKNET, createDrandClient } from "@condlock/core";
import { Escrow } from "./escrow.js";
import { migrate, pgliteClient, postgresClient, type SqlClient } from "./db.js";
import { AwsKms } from "./keywrap/aws-kms.js";
import { MockKms } from "./keywrap/mock-kms.js";
import { ThresholdKeyWrapper } from "./keywrap/threshold.js";
import { KeyWrapRegistry, type KeyWrapper } from "./keywrap/types.js";
import type { KeyReleaser } from "./verifier/protocol.js";
import { InProcessReleaser, SocketReleaser, type SocketTarget } from "./verifier/transport.js";
import { KeyReleaseVerifier } from "./verifier/verifier.js";

export interface Built {
  escrow: Escrow;
  db: SqlClient;
  adminToken?: string;
  /** Where the verifier listens, when it's a separate process (for the credential relay). */
  verifierTarget?: SocketTarget;
}

function kmsFromEnv(env: NodeJS.ProcessEnv, provider: string | undefined, keyId: string | undefined, what: string, scheme?: string): KeyWrapper {
  if ((provider ?? "aws") === "aws") {
    if (!keyId) throw new Error(`${what} key ID is required for an aws provider`);
    return new AwsKms({ keyId, ...(env.AWS_REGION ? { region: env.AWS_REGION } : {}) });
  }
  if (provider === "mock") {
    if (env.NODE_ENV === "production") throw new Error(`a mock ${what} is not allowed in production`);
    return new MockKms(scheme ? { scheme } : {});
  }
  throw new Error(`unknown ${what} provider ${provider}`);
}

/** All wrappers this escrow knows, primary first. Old single-key locks stay unwrappable. */
export function keyWrappersFromEnv(env: NodeJS.ProcessEnv): KeyWrapRegistry {
  const kms = kmsFromEnv(env, env.KMS_PROVIDER, env.KMS_KEY_ID, "KMS");
  if (!env.KEY_SPLIT) return new KeyWrapRegistry(kms);
  if (env.KEY_SPLIT !== "2of3") throw new Error('KEY_SPLIT must be "2of3"');
  const second = kmsFromEnv(env, env.SECOND_PROVIDER, env.SECOND_KMS_KEY_ID, "second provider", "mock-second-provider/v1");
  return new KeyWrapRegistry(new ThresholdKeyWrapper({ escrowKms: kms, secondProvider: second }), [kms]);
}

export async function dbFromEnv(env: NodeJS.ProcessEnv): Promise<SqlClient> {
  if (env.DATABASE_URL) return postgresClient(env.DATABASE_URL);
  const spec = env.ESCROW_DB ?? "";
  if (spec === "pglite:memory") return pgliteClient();
  if (spec.startsWith("pglite:")) return pgliteClient(spec.slice("pglite:".length));
  throw new Error("set DATABASE_URL, or ESCROW_DB=pglite:memory for local development");
}

export function verifierTargetFromEnv(env: NodeJS.ProcessEnv): SocketTarget | undefined {
  if (env.VERIFIER_SOCKET) return { path: env.VERIFIER_SOCKET };
  if (env.VERIFIER_ADDR) {
    const m = /^([^:]+):(\d+)$/.exec(env.VERIFIER_ADDR);
    if (!m) throw new Error("VERIFIER_ADDR must be host:port");
    return { host: m[1]!, port: Number(m[2]) };
  }
  return undefined;
}

export function releaserFromEnv(env: NodeJS.ProcessEnv, keys: KeyWrapRegistry): KeyReleaser {
  const target = verifierTargetFromEnv(env);
  if (target) return new SocketReleaser(target);
  if (env.VERIFIER_INPROCESS === "1") {
    if (env.NODE_ENV === "production") throw new Error("VERIFIER_INPROCESS is not allowed in production");
    // Local development only: no NFL checker here (run src/verifier/main.ts for that).
    return new InProcessReleaser(new KeyReleaseVerifier({ keys }));
  }
  throw new Error("set VERIFIER_SOCKET or VERIFIER_ADDR (or VERIFIER_INPROCESS=1 for local development)");
}

export async function buildFromEnv(env: NodeJS.ProcessEnv = process.env): Promise<Built> {
  const keys = keyWrappersFromEnv(env);
  const releaser = releaserFromEnv(env, keys);
  const db = await dbFromEnv(env);
  await migrate(db);
  const escrow = new Escrow({ db, keys, releaser, drand: createDrandClient(QUICKNET) });
  const verifierTarget = verifierTargetFromEnv(env);
  return {
    escrow,
    db,
    ...(env.ESCROW_ADMIN_TOKEN ? { adminToken: env.ESCROW_ADMIN_TOKEN } : {}),
    ...(verifierTarget ? { verifierTarget } : {}),
  };
}
