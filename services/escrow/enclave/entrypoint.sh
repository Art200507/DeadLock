#!/bin/sh
# Runs inside the Nitro Enclave. TEMPLATE (see docs/ENCLAVE.md).
set -eu

: "${AWS_REGION:?AWS_REGION must be set at build time (ENV) for the KMS hostname}"

# 1. KMS over the parent's vsock-proxy (CID 3 = parent). TLS still terminates here, in the
#    enclave, against the real kms.<region>.amazonaws.com certificate: the parent only relays bytes.
echo "127.0.0.1 kms.${AWS_REGION}.amazonaws.com" >> /etc/hosts
socat TCP-LISTEN:443,bind=127.0.0.1,fork,reuseaddr "VSOCK-CONNECT:3:${KMS_PROXY_VSOCK_PORT}" &

# 2. Expose the verifier's Unix socket on vsock so the parent's API can reach it.
socat "VSOCK-LISTEN:${VERIFIER_VSOCK_PORT},fork,reuseaddr" "UNIX-CONNECT:${VERIFIER_SOCKET}" &

# 3. AWS credentials: the enclave has no IMDS. See "Credentials" in docs/ENCLAVE.md
#    (not implemented yet: the parent must deliver short-lived role credentials).

exec node /app/dist/verifier/main.js
