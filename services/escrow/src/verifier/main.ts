/**
 * Verifier entry point: the process that runs inside the enclave (or next to the API locally).
 *
 *   VERIFIER_SOCKET        Unix socket path to listen on (socat bridges vsock to it in the enclave)
 *   AWS_REGION             KMS region; credentials are passed in from the parent (docs/ENCLAVE.md).
 *                          No key ID: the verifier only unwraps, using the key ID in each wrapped key.
 *   KMS_ENDPOINT           local bridge to the parent's vsock-proxy for kms.<region>.amazonaws.com
 *   NSM_ATTEST_COMMAND     helper that prints an attestation document for the key on stdin
 */
import { AwsKms } from "../keywrap/aws-kms.js";
import { CommandAttestationProvider } from "../keywrap/recipient.js";
import { KeyWrapRegistry } from "../keywrap/types.js";
import { serveVerifier } from "./transport.js";
import { KeyReleaseVerifier } from "./verifier.js";

const env = process.env;
const socket = env.VERIFIER_SOCKET ?? "/tmp/condlock-verifier.sock";
if (!env.NSM_ATTEST_COMMAND) throw new Error("NSM_ATTEST_COMMAND is required: the verifier only decrypts with attestation");

const kms = new AwsKms({
  keyId: env.KMS_KEY_ID ?? "unwrap-only",
  ...(env.AWS_REGION ? { region: env.AWS_REGION } : {}),
  ...(env.KMS_ENDPOINT ? { endpoint: env.KMS_ENDPOINT } : {}),
  attestation: new CommandAttestationProvider(env.NSM_ATTEST_COMMAND),
});
await serveVerifier(new KeyReleaseVerifier({ keys: new KeyWrapRegistry(kms) }), { path: socket });
console.log(`condlock verifier listening on ${socket}`);
