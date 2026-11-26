# @condlock/escrow

The key escrow service: a Hono API plus a separate **key-release verifier**, designed to run
in an AWS Nitro Enclave. Postgres holds locks, devices and the append-only audit log. KMS wraps
each vault's data key, or, with `KEY_SPLIT=2of3`, one of three Shamir shares of it.

```
src/app.ts             HTTP routes, Ed25519 request signatures, body limits
src/escrow.ts          sealing, "released once", audit log (API side: KMS Encrypt only)
src/verifier/          key release: protocol, verifier, transports, secrets store, credential relay, enclave main
src/verifiers/         condition checkers: NFL (two sources must agree) and the provider clients
src/egress/            outbound HTTPS from the verifier: allowlisted dialer, TLS inside, byte forwarder
src/keywrap/           KeyWrapper seam: AWS KMS (+ attestation/Recipient), 2-of-3 threshold, mocks
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
| `POST /locks` | `{ vaultId, condition, failsafeAt, dek, guardian? }`: wraps the DEK and stores only the wrapped key. Returns the sealed lock (with `guardian.share` for 2-of-3 locks). |
| `GET /locks/:id` | status, condition, its SHA-256, times, key scheme, guardian share, the latest verifier result |
| `POST /locks/:id/unlock` | optional body `{ guardianShare }`. `200 { dek, via }` once, `423 still locked` (with `reason`, and `resolved: true` once only the fail-safe can open it), `409 already released`, `503` for `drand-unavailable`, `verifier-unavailable`, `sources-unavailable` or `insufficient-shares` |
| `GET /locks/:id/log` | the audit log for the vault |

No route edits or deletes a lock or its condition.

### Conditions

```jsonc
{ "type": "time", "unlockAt": "2027-01-01T09:00:00Z" }

{ "type": "nfl",
  "game": { "apiSportsId": "7803", "theSportsDbId": "1942349",
            "home": "Kansas City Chiefs", "away": "San Francisco 49ers",
            "kickoffAt": "2024-02-11T23:30:00Z" },
  "team": "Kansas City Chiefs", "outcome": "win",          // or "loss"
  "ifTie": "stay-locked",                                   // or "unlock"
  "ifPostponed": "wait",                                    // or "unlock" | "stay-locked"
  "ifCancelled": "stay-locked" }                            // or "unlock"
```

Every field is sealed. "stay-locked" means only the fail-safe opens it. Team names are as both
providers spell them; the comparison ignores case and punctuation. TheSportsDB links its events
to API-Sports IDs (`idAPIfootball`), and the verifier checks that link when it's present.

## How a key is released

1. The API gets the latest drand beacon and sends the verifier the lock's terms, the wrapped
   key, the beacon and, if given, the guardian's share. There is no field for scores or results.
2. The verifier BLS-verifies the beacon against the pinned drand chain and recomputes the
   **seal** (sha256 of vault ID + condition + fail-safe). Then it decides:
   - **Fail-safe:** the beacon's round is at least the fail-safe's round. No other check runs.
   - **Time:** the beacon's round is at least `roundForTime(unlockAt)`.
   - **NFL:** see below.
3. Only then does it unwrap, with `EncryptionContext { app, vaultId, seal }`. In an enclave, KMS
   Decrypt carries a Recipient attestation, so KMS answers with a CMS envelope only the enclave
   can open.
4. The API marks the lock `released` or `failsafe` with a single conditional UPDATE: a second
   or concurrent request gets 409.

The API host can't release early in any of these ways:
- **Lying about time** fails the beacon check.
- **Lying about the terms** changes the seal, so KMS refuses.
- **Moving a wrapped key to another vault** changes the context, so KMS refuses.
- **Calling KMS directly** is denied by the key policy (enclave setup).
- **Faking a score** isn't possible: the verifier fetches results itself over TLS that ends
  inside the enclave. The host relays bytes it can't read or forge.

### The NFL verifier (`src/verifiers/`)

- **Before kickoff** (by drand time): not met, and no API calls.
- **Fetching:** the verifier fetches API-Sports (`/games?id=`) and TheSportsDB
  (`lookupevent.php?id=`) itself. If either fails, the answer is 503 `sources-unavailable`,
  never a release.
- **Same game:** both sources must name the sealed home and away teams. TheSportsDB's link to
  the API-Sports ID must match. Otherwise it's a disagreement.
- **Status:** both must report the same final, postponed or cancelled state. If one still says
  scheduled or in progress, it waits. If their terminal states or final scores differ, it stays
  locked (423, `sourcesDisagree`) until they agree.
- **The sealed rules:**
  - final: a win or loss for `team` opens the lock if it's the sealed `outcome`; a tie follows
    `ifTie`;
  - postponed follows `ifPostponed` (`wait` keeps checking the same IDs);
  - cancelled follows `ifCancelled`.

  A result that won't open the lock comes back as 423 with `resolved: true`; only the fail-safe
  opens it after that.
- **Audit:** every NFL check records a `verifier-check` audit entry with both sources' reports.
  `GET /locks/:id` shows the latest one.

### Egress and credentials

The enclave has no network card. The verifier reaches out through `RoutedDialer`, an allowlist
of `host:443` to local port. In the enclave, socat sends each port over vsock to the parent's
`vsock-proxy`. TLS runs in the verifier and is checked against Node's bundled CA roots, so the
parent can block traffic but can't read or forge it. AWS KMS uses the same path, through the
SDK's `NodeHttpHandler` with the egress agent.

The parent delivers what the enclave can't fetch itself over the verifier socket, as
`{ op: "secrets", aws, sports }`. That covers the instance role's short-lived AWS credentials
and the two API keys. `CREDENTIAL_RELAY=1` on the API process does this and refreshes the
credentials before they expire. See [docs/ENCLAVE.md](../../docs/ENCLAVE.md).

### 2-of-3 key split (`KEY_SPLIT=2of3`)

The DEK is split with [`shamir-secret-sharing`](https://github.com/privy-io/shamir-secret-sharing)
(audited by Cure53 and Zellic) into three shares:

| Share | Held by | How it's protected |
|---|---|---|
| a | the escrow's KMS key | KMS, context = vault + seal; policy: only the attested enclave decrypts |
| b | a second, independent provider | its own key behind `KeyWrapper`, also attestation-bound |
| c | a trusted person (the guardian) | [age](https://age-encryption.org) to their public key (`age1…`, or post-quantum `age1pq1…`) |

- **Any two shares release:** normally a + b, inside the verifier, after the condition check.
- **If one provider is down:** the unlock returns 503 `insufficient-shares` and names the
  holder that failed. The guardian decrypts their share with the standard tool,
  `age -d -i guardian.key share.age | base64`, from `GET /locks/:id` → `guardian.share`. Retry
  with `{ "guardianShare": "<base64>" }`; the verifier still checks the condition first.
- **No single account is enough:** not AWS, not the second provider, not the guardian, and not
  whoever runs the database.
- **Binding:** every share is tied to the vault and the seal. A commitment, an HMAC keyed by
  the DEK, catches a wrong or corrupted share, which Shamir can't detect by itself.
- **Fail-safe and old locks:** the tlock fail-safe is unchanged. Single-key locks keep
  unwrapping, because their wrapper stays registered.

Options for the second provider (only the mock is implemented):
- **A KMS key in a separate AWS account** with a different owner, using the same PCR0 policy
  (`enclave/second-provider-key-policy.json`). It works with Nitro attestation today. The admins
  are independent, but the vendor is the same AWS.
- **GCP Cloud KMS with Confidential Space, or Azure Managed HSM Secure Key Release.** These give
  real vendor independence, but their key-release policies check their own platforms'
  attestation, not AWS Nitro's. Share b would need a second verifier running in that cloud's
  TEE, plus a protocol between the two verifiers. I haven't checked current details for either.
- **Self-hosted Vault/OpenBao (Transit)** on infrastructure someone else runs. It's simple, but
  there's no attestation: that operator could unwrap share b without the condition. It's only
  as strong as trusting that operator, which is like a second guardian.

## Running locally

```sh
cp .env.example .env          # defaults: PGlite in memory, mock KMS, in-process verifier
pnpm --filter @condlock/escrow dev
pnpm --filter @condlock/escrow test
```

Tests use:
- PGlite (real Postgres in WASM, in-process);
- the mock KMS and mock NSM, and a mocked drand network;
- a real Unix socket for the verifier;
- mock API-Sports, TheSportsDB and KMS HTTPS servers. Their certificates come from a throwaway
  test CA generated in memory, and they're reached through byte forwarders that stand in for
  vsock-proxy.

They need no network and no cloud.

## The live sports test (you run it)

`test/live/sports.live.test.ts` fetches one real game from both providers and runs the same
parsing and decision code as the verifier. The default game is Super Bowl LVIII, API-Sports
game 7803 and TheSportsDB event 1942349. It's skipped unless enabled:

1. Get a free API-Sports key (sign up at api-sports.io; American Football API, 100 requests a
   day). TheSportsDB's public free key is `123`.
2. In `services/escrow/.env` (git-ignored):
   ```sh
   CONDLOCK_LIVE_SPORTS=1
   APISPORTS_KEY=...
   THESPORTSDB_KEY=123
   ```
3. `pnpm --filter @condlock/escrow test:live-sports`. Expected: 2 tests pass and both reports are
   printed, using about 3 requests to each API. Free API-Sports plans only cover some seasons.
   An error like `plan: ...` means you should pick a game from a season your plan includes, set
   with `CONDLOCK_LIVE_APISPORTS_ID`, `CONDLOCK_LIVE_THESPORTSDB_ID`, `CONDLOCK_LIVE_HOME` and
   `CONDLOCK_LIVE_AWAY`.

TheSportsDB's format matches its live API. The API-Sports parser follows their documented
format. This test is the first check against a real API-Sports response.

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

Implement `KeyWrapper` (`src/keywrap/types.ts`): a `scheme` name, `wrap(dek, context, options?)`
and `unwrap(wrapped, context, options?)`, with the context (vault ID + seal) bound as associated
data. Register it in a `KeyWrapRegistry`, as primary for new locks; old locks keep their own
scheme.

`ThresholdKeyWrapper` (`src/keywrap/threshold.ts`) is a worked example of a composite layer: it
wraps shares with two sub-wrappers and age. A **post-quantum hybrid** could follow the same
shape, with an outer ML-KEM layer around a KMS-wrapped key. The guardian share already accepts
age's hybrid post-quantum recipients (`age1pq1…`).
