# Enclave image for the key-release verifier. TEMPLATE: built and run by you on an
# enclave-enabled EC2 instance (docs/ENCLAVE.md). Every byte here goes into PCR0, so pin
# everything: the base image digest, the lockfile, and the nsm-attest helper.
#
# Build context: the repo root, after
#   pnpm install && pnpm -r build
#   pnpm --filter @condlock/escrow deploy --prod services/escrow/enclave/build/app
# and with your compiled `nsm-attest` helper at services/escrow/enclave/nsm-attest.
# (Both paths are git-ignored.)

FROM node:22-bookworm-slim@sha256:REPLACE_WITH_PINNED_DIGEST

RUN apt-get update \
 && apt-get install -y --no-install-recommends socat ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY services/escrow/enclave/build/app/ /app/
COPY services/escrow/enclave/nsm-attest /usr/local/bin/nsm-attest
COPY services/escrow/enclave/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/nsm-attest /usr/local/bin/entrypoint.sh

# The region and the egress allowlist are baked in, so they are part of PCR0: a parent can't add
# a host. The key ARNs are NOT: the key policies need this image's PCR0 before the keys exist,
# and the verifier decrypts with the key ID stored in each wrapped key (only ciphertext under
# the attested keys is protected, which is the point).
ENV AWS_REGION=REPLACE_REGION \
    NODE_ENV=production \
    VERIFIER_SOCKET=/tmp/condlock-verifier.sock \
    NSM_ATTEST_COMMAND=/usr/local/bin/nsm-attest \
    VERIFIER_VSOCK_PORT=5005 \
    SECOND_PROVIDER=aws \
    EGRESS_ROUTES=kms.REPLACE_REGION.amazonaws.com=127.0.0.1:8000,v1.american-football.api-sports.io=127.0.0.1:8001,www.thesportsdb.com=127.0.0.1:8002

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
