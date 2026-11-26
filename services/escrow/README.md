# @condlock/escrow

The key escrow service: a Hono API plus a separate **key-release verifier**, designed to run
in an AWS Nitro Enclave. Postgres holds locks, devices and the append-only audit log. KMS wraps
each vault's data key.

```
src/app.ts             HTTP routes, Ed25519 request signatures, body limits
src/escrow.ts          sealing, "released once", audit log (API side: KMS Encrypt only)
src/verifier/          key release: protocol, verifier, socket/in-process transports, enclave main
src/keywrap/           KeyWrapper seam: AWS KMS (+ attestation/Recipient), mock KMS + mock NSM
src/conditions.ts      condition validation, canonical JSON, seal hash
src/db.ts              SqlClient for node-postgres and PGlite, migration runner
../../db/migrations    schema + triggers (audit append-only, sealed fields immutable)
enclave/               Dockerfile, entrypoint and KMS key policies (templates; see docs/ENCLAVE.md)
```

## API

Every `/locks` request must be signed by a registered device (Ed25519). Clients send four
`x-condlock-*` headers (device, timestamp, nonce, signature) over
`METHOD \n path \n timestamp \n nonce \n sha256(body)`. The server rejects timestamps more than
5 minutes off its own clock, and nonces that were already used.

| Route | What it does |
|---|---|
| `POST /devices` | register a device public key (`Authorization: Bearer $ESCROW_ADMIN_TOKEN`) |
| `POST /locks` | `{ vaultId, condition, failsafeAt, dek }`: wraps the DEK and stores only the wrapped key. Returns the sealed lock. |
| `GET /locks/:id` | status, condition, its SHA-256, times, the latest verifier result |
| `POST /locks/:id/unlock` | `200 { dek, via }` once, `423 still locked`, `409 already released`, `503` if drand or the verifier is unavailable |
| `GET /locks/:id/log` | the audit log for the vault |

No route edits or deletes a lock or its condition.

## How a key is released

1. The API gets the latest drand beacon and sends the verifier the lock's terms, the wrapped
   key and the beacon.
2. The verifier BLS-verifies the beacon against the pinned drand chain, recomputes the **seal**
   (sha256 of vault ID + condition + fail-safe), and decides from drand rounds alone.
3. Only then does it call KMS Decrypt with `EncryptionContext { app, vaultId, seal }`. In an
   enclave, the call carries a Recipient attestation, so KMS answers with a CMS envelope only
   the enclave can open.
4. The API marks the lock `released` or `failsafe` with a single conditional UPDATE: a second
   or concurrent request gets 409.

The API host can't release early in any of these ways:
- **Lying about time** fails the beacon check.
- **Lying about the terms** changes the seal, so KMS refuses.
- **Moving a wrapped key to another vault** changes the context, so KMS refuses.
- **Calling KMS directly** is denied by the key policy (enclave setup).

## Running locally

```sh
cp .env.example .env          # defaults: PGlite in memory, mock KMS, in-process verifier
pnpm --filter @condlock/escrow dev
pnpm --filter @condlock/escrow test
```

Tests use PGlite (real Postgres in WASM, in-process), the mock KMS and mock NSM, a mocked drand
network, and a real Unix socket for the verifier transport. They need no network and no cloud.

## The real-KMS test (you run it)

`test/real/real-kms.test.ts` checks the AWS KMS adapter and the full API flow against a real key.
It is skipped unless `CONDLOCK_REAL_KMS_KEY_ID` is set, and it creates no resources.

1. Create a **separate test key**, not the enclave key, whose policy lets your own IAM user or
   role Encrypt and Decrypt. Start from `enclave/test-key-policy.json` (fill in `ACCOUNT_ID` and
   your principal):
   ```sh
   aws kms create-key --description "condition-lock TEST key" --policy file://enclave/test-key-policy.json
   ```
   A KMS key costs about $1/month (prorated); the test's ~6 requests fit in the free tier.
2. Put the details in `services/escrow/.env` (git-ignored):
   ```sh
   CONDLOCK_REAL_KMS_KEY_ID=arn:aws:kms:us-east-1:ACCOUNT_ID:key/...
   AWS_REGION=us-east-1
   AWS_PROFILE=your-profile         # or any standard AWS credential source
   ```
3. Run it:
   ```sh
   pnpm --filter @condlock/escrow test:real-kms
   ```
   Expected: 2 tests pass. They cover round-trip and wrong-vault or edited-seal refusals, plus a
   full lock → still locked → unlock flow through the API with in-memory Postgres.
4. Afterwards, schedule the test key for deletion:
   `aws kms schedule-key-deletion --key-id <arn> --pending-window-in-days 7`.

## Adding a key-protection layer

Implement `KeyWrapper` (`src/keywrap/types.ts`): a `scheme` name, `wrap(dek, context)` and
`unwrap(wrapped, context)`, with the context (vault ID + seal) bound as associated data.
Register it in a `KeyWrapRegistry`, as primary for new locks; old locks keep their own scheme.

Some layers this shape allows:
- **Post-quantum hybrid:** an outer ML-KEM layer around a KMS-wrapped key.
- **Threshold or split-key:** Shamir shares wrapped by N sub-wrappers, k required.

The `WrappingLayer` test in `test/keywrap.test.ts` shows a composite layer over the mock KMS.
