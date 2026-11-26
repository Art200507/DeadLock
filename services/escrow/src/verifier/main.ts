/**
 * Verifier entry point: the process that runs inside the enclave (or next to the API locally).
 *
 *   VERIFIER_SOCKET     Unix socket to listen on (socat bridges the enclave's vsock port to it)
 *   AWS_REGION          KMS region. No key ID: the verifier only unwraps, with each wrapped key's ID.
 *                       Credentials arrive from the parent over the same socket (op "secrets").
 *   EGRESS_ROUTES       allowlist of outbound hosts and the local ports that reach them, e.g.
 *                       "kms.us-east-1.amazonaws.com=127.0.0.1:8000,v1.american-football.api-sports.io=127.0.0.1:8001,
 *                        www.thesportsdb.com=127.0.0.1:8002". Each local port is socat → vsock → the parent's
 *                       vsock-proxy → host:443. TLS terminates here, checked against Node's bundled roots.
 *   NSM_ATTEST_COMMAND  helper that prints an attestation document for the public key on stdin
 *   SECOND_PROVIDER     "aws" if share b of 2-of-3 locks lives in another account's KMS key (default),
 *                       "none" to support only single-key locks.
 *   DEV_NO_ATTESTATION=1  local development only: decrypt without attestation, direct network.
 */
import { NodeHttpHandler } from "@smithy/node-http-handler";
import { DirectDialer, RoutedDialer, parseRoutes } from "../egress/dialer.js";
import { EgressHttps } from "../egress/https.js";
import { AwsKms } from "../keywrap/aws-kms.js";
import { CommandAttestationProvider } from "../keywrap/recipient.js";
import { ThresholdKeyWrapper } from "../keywrap/threshold.js";
import { KeyWrapRegistry, type KeyWrapper } from "../keywrap/types.js";
import { NflChecker } from "../verifiers/nfl.js";
import { ApiSportsNfl, TheSportsDb } from "../verifiers/sports.js";
import { SecretStore } from "./secrets.js";
import { serveVerifier } from "./transport.js";
import { KeyReleaseVerifier } from "./verifier.js";

const env = process.env;
const socket = env.VERIFIER_SOCKET ?? "/tmp/condlock-verifier.sock";
const dev = env.DEV_NO_ATTESTATION === "1";
if (dev && env.NODE_ENV === "production") throw new Error("DEV_NO_ATTESTATION is not allowed in production");
if (!dev && !env.NSM_ATTEST_COMMAND) throw new Error("NSM_ATTEST_COMMAND is required: the verifier only decrypts with attestation");
if (!dev && !env.EGRESS_ROUTES) throw new Error("EGRESS_ROUTES is required inside the enclave");

const secrets = new SecretStore();
const dialer = env.EGRESS_ROUTES ? new RoutedDialer(parseRoutes(env.EGRESS_ROUTES)) : new DirectDialer();
const http = new EgressHttps({ dialer });

const kms = new AwsKms({
  keyId: "unwrap-only",
  ...(env.AWS_REGION ? { region: env.AWS_REGION } : {}),
  ...(dev ? {} : { attestation: new CommandAttestationProvider(env.NSM_ATTEST_COMMAND!) }),
  credentials: secrets.awsCredentials,
  requestHandler: new NodeHttpHandler({ httpsAgent: http.agent }),
});
// The same AwsKms serves share b when the second provider is a KMS key in another account: it
// decrypts with the key ID stored in each share, and that key's policy also requires PCR0.
const wrappers: KeyWrapper[] = [kms];
const keys =
  (env.SECOND_PROVIDER ?? "aws") === "aws"
    ? new KeyWrapRegistry(new ThresholdKeyWrapper({ escrowKms: kms, secondProvider: kms }), wrappers)
    : new KeyWrapRegistry(kms);

const nfl = new NflChecker({
  apiSports: new ApiSportsNfl({ http, apiKey: secrets.apiSportsKey }),
  theSportsDb: new TheSportsDb({ http, apiKey: secrets.theSportsDbKey }),
});

await serveVerifier(new KeyReleaseVerifier({ keys, nfl, secrets }), { path: socket });
console.log(`condlock verifier listening on ${socket}; egress: ${dialer instanceof RoutedDialer ? dialer.hosts.join(", ") : "direct (dev)"}`);
