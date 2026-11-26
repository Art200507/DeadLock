/**
 * Parent side of credential delivery. The enclave has no network and no instance metadata
 * service, so the parent reads the instance role's short-lived credentials (IMDS, via the AWS
 * SDK's default chain) and pushes them, plus the sports API keys, over the verifier channel.
 * It re-pushes before they expire, and retries on failure (e.g. the enclave restarted).
 *
 * This hands the enclave nothing the parent doesn't already hold, and the KMS key policy still
 * requires the enclave's attestation for Decrypt, so the parent gains nothing either.
 */
import type { AwsCredentialsMessage, SecretsMessage } from "./protocol.js";
import { pushSecrets, type SocketTarget } from "./transport.js";

export interface CredentialSource {
  (): Promise<{ accessKeyId: string; secretAccessKey: string; sessionToken?: string; expiration?: Date }>;
}

export interface RelayOptions {
  target: SocketTarget;
  /** AWS credentials to forward (e.g. defaultProvider() from @aws-sdk/credential-provider-node). */
  aws?: CredentialSource;
  sports?: { apiSportsKey?: string; theSportsDbKey?: string };
  /** Push at least this often (default 10 minutes), and 5 minutes before credentials expire. */
  refreshMs?: number;
  retryMs?: number;
  onPush?: (stored: string[]) => void;
  onError?: (err: Error) => void;
}

export interface Relay {
  /** Push once now; resolves with when the next push is due (ms). */
  pushNow(): Promise<number>;
  stop(): void;
}

export function startCredentialRelay(opts: RelayOptions): Relay {
  const refreshMs = opts.refreshMs ?? 10 * 60_000;
  const retryMs = opts.retryMs ?? 15_000;
  let timer: NodeJS.Timeout | undefined;
  let stopped = false;

  const pushNow = async (): Promise<number> => {
    const msg: SecretsMessage = { v: 1, op: "secrets" };
    let next = refreshMs;
    if (opts.aws) {
      const c = await opts.aws();
      const aws: AwsCredentialsMessage = { accessKeyId: c.accessKeyId, secretAccessKey: c.secretAccessKey };
      if (c.sessionToken) aws.sessionToken = c.sessionToken;
      if (c.expiration) {
        aws.expiration = c.expiration.toISOString();
        next = Math.max(30_000, Math.min(next, c.expiration.getTime() - Date.now() - 5 * 60_000));
      }
      msg.aws = aws;
    }
    if (opts.sports) msg.sports = opts.sports;
    const res = await pushSecrets(opts.target, msg);
    if (!res.ok) throw new Error(`verifier refused the secrets: ${res.message}`);
    opts.onPush?.(res.stored);
    return next;
  };

  const loop = () => {
    if (stopped) return;
    pushNow().then(
      (next) => {
        if (!stopped) timer = setTimeout(loop, next);
      },
      (err: Error) => {
        opts.onError?.(err);
        if (!stopped) timer = setTimeout(loop, retryMs);
      },
    );
  };
  loop();

  return {
    pushNow,
    stop() {
      stopped = true;
      if (timer) clearTimeout(timer);
    },
  };
}
