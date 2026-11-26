#!/bin/sh
# Runs inside the Nitro Enclave. TEMPLATE (see docs/ENCLAVE.md).
set -eu

: "${AWS_REGION:?AWS_REGION must be set at build time (ENV) for the KMS hostname}"
: "${EGRESS_ROUTES:?EGRESS_ROUTES must be set at build time (ENV): it is the egress allowlist}"

# 1. Egress: one local port per allowlisted host, each bridged to the same vsock port on the
#    parent (CID 3), where `vsock-proxy <port> <host> 443` forwards the bytes. TLS terminates in
#    the verifier (node), checked against Node's bundled CA roots, so the parent relays ciphertext.
#    EGRESS_ROUTES looks like "kms.us-east-1.amazonaws.com=127.0.0.1:8000,...".
echo "$EGRESS_ROUTES" | tr ',' '\n' | while IFS= read -r route; do
  port="${route##*:}"
  socat "TCP-LISTEN:${port},bind=127.0.0.1,fork,reuseaddr" "VSOCK-CONNECT:3:${port}" &
done

# 2. Expose the verifier's Unix socket on vsock so the parent can reach it: the API's release
#    requests, and the parent's credential relay (short-lived role credentials + sports API keys,
#    op "secrets"), which is how AWS credentials get into the enclave.
socat "VSOCK-LISTEN:${VERIFIER_VSOCK_PORT},fork,reuseaddr" "UNIX-CONNECT:${VERIFIER_SOCKET}" &

exec node /app/dist/verifier/main.js
