/**
 * In-memory store for what the parent delivers into the enclave over the verifier channel:
 * short-lived AWS credentials (the instance role's, from IMDS) and the sports API keys. Nothing
 * is written to disk. Passing the role's credentials grants the enclave nothing the parent
 * doesn't already have: the KMS key policy still requires the enclave's attestation to decrypt.
 */
import type { AwsCredentialsMessage, SecretsMessage, SecretsResponse } from "./protocol.js";

export interface AwsCredentialIdentity {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  expiration?: Date;
}

export class MissingSecretError extends Error {
  override name = "MissingSecretError";
}

const str = (v: unknown, max = 4096) => typeof v === "string" && v.length > 0 && v.length <= max;

export class SecretStore {
  private aws: AwsCredentialIdentity | undefined;
  private sports: { apiSportsKey?: string; theSportsDbKey?: string } = {};
  /** For tests and diagnostics: how many times each kind was delivered. */
  deliveries = { aws: 0, sports: 0 };

  constructor(private readonly now: () => Date = () => new Date()) {}

  accept(input: unknown): SecretsResponse {
    const bad = (message: string): SecretsResponse => ({ v: 1, ok: false, code: "bad-request", message });
    const m = input as Partial<SecretsMessage>;
    if (m?.v !== 1 || m.op !== "secrets") return bad("not a secrets message");
    const stored: string[] = [];
    if (m.aws !== undefined) {
      const a = m.aws as Partial<AwsCredentialsMessage>;
      if (!str(a.accessKeyId, 128) || !str(a.secretAccessKey, 256) || (a.sessionToken !== undefined && !str(a.sessionToken))) {
        return bad("aws credentials are malformed");
      }
      if (a.expiration !== undefined && Number.isNaN(Date.parse(a.expiration))) return bad("aws.expiration");
      this.aws = {
        accessKeyId: a.accessKeyId!,
        secretAccessKey: a.secretAccessKey!,
        ...(a.sessionToken ? { sessionToken: a.sessionToken } : {}),
        ...(a.expiration ? { expiration: new Date(a.expiration) } : {}),
      };
      this.deliveries.aws++;
      stored.push("aws");
    }
    if (m.sports !== undefined) {
      const s = m.sports as Record<string, unknown>;
      for (const k of ["apiSportsKey", "theSportsDbKey"] as const) {
        if (s[k] !== undefined && !str(s[k], 256)) return bad(`sports.${k}`);
      }
      this.sports = {
        ...this.sports,
        ...(typeof s.apiSportsKey === "string" ? { apiSportsKey: s.apiSportsKey } : {}),
        ...(typeof s.theSportsDbKey === "string" ? { theSportsDbKey: s.theSportsDbKey } : {}),
      };
      this.deliveries.sports++;
      stored.push("sports");
    }
    return { v: 1, ok: true, op: "secrets", stored };
  }

  /** An AWS SDK credential provider. */
  readonly awsCredentials = async (): Promise<AwsCredentialIdentity> => {
    if (!this.aws) throw new MissingSecretError("no AWS credentials have been delivered to the verifier yet");
    if (this.aws.expiration && this.aws.expiration.getTime() <= this.now().getTime()) {
      throw new MissingSecretError("the delivered AWS credentials have expired; the parent should push fresh ones");
    }
    return { ...this.aws };
  };

  readonly apiSportsKey = () => this.sports.apiSportsKey;
  readonly theSportsDbKey = () => this.sports.theSportsDbKey;
}
