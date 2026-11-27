# Condition Lock — design

Full design doc: https://claude.ai/artifact/6hcU82mXDqALEXWDSzxmNe

## Summary

Condition Lock is a commitment device: it encrypts files on the laptop, shreds the
originals, and keeps the only key in a cloud escrow that hands it back once a sealed
condition is verified true. The key never sits on the device and is never reachable
by the owner alone.

- **Encryption.** Each vault has a random 256-bit data key (DEK). Files are streamed
  in 1 MiB chunks, each AES-256-GCM with a unique nonce and vault ID + file ID +
  chunk index as associated data, so chunks can't be swapped, reordered or truncated.
  File names and sizes live in an encrypted manifest. Folders are packed to tar first;
  every file is opaque bytes. No custom crypto (Node WebCrypto, official tlock libs).
- **Escrow.** A small API with no "release" button. The DEK is wrapped with one AWS KMS
  key (encryption context = vault ID); only the service role may Decrypt. A scheduled
  verifier records "met" with evidence; unlock returns the DEK once, to a registered
  device key. Append-only audit log. *(As built, milestones 4 and 5: Decrypt only in an
  attested Nitro Enclave verifier that checks the condition at unlock time, plus an optional
  2-of-3 split.)*
- **Conditions (MVP).** Time-lock (server clock + drand round, plus a tlock copy that
  enforces time with no trust in the server) and NFL result (API-Sports and TheSportsDB
  must agree). Conditions are sealed; edits can only make a lock stricter.
- **Fail-safe.** Every vault has a fail-safe date (default 1 year, min 30 days); the DEK
  is tlock-encrypted to it so the vault opens offline even if the server is gone.
- **Threat model.** The adversary is the owner on a weak night. Stops casual and
  moderate cheating (clock changes, local key hunting, editing conditions); cannot stop
  a pre-planned bypass (copies kept before locking, admin access to one's own cloud
  account — mitigated by drand, a custodian, or split keys).
- **Stack.** TypeScript on Node 22, pnpm workspace; Hono on serverless; Postgres
  (Neon/Supabase); AWS KMS; Vercel Schedules or EventBridge every 15 min.

## Milestones

1. **Core crypto** — chunked AES-256-GCM + encrypted manifest; tests for round-trip,
   flipped byte, swapped chunks, wrong key. ✅
2. **tlock** — wrap/unwrap of the DEK with tlock-js on drand quicknet; round-for-time
   math; tests for locked-then-open (real network), wrong round, tampering, mocked drand. ✅
3. **CLI, local only** — `condlock lock | unlock | status | log`; tlock time-lock + fail-safe,
   typed confirmation, verify-then-delete, copies checklist, hash-chained local log. ✅
4. **Escrow service** — Hono API, Postgres migrations, KMS envelope wrapping (vault ID + seal as
   context), Ed25519 device signatures, append-only audit log, and an enclave-ready key-release
   verifier with attestation-bound KMS decrypt. Tested with mocks; real KMS and Nitro setup are
   manual ([ENCLAVE.md](ENCLAVE.md)). ✅
5. **Verifiers, egress, key split.** Time (drand) and NFL (API-Sports and TheSportsDB must agree;
   sealed tie/postponed/cancelled rules) checked inside the verifier. The verifier makes its own
   TLS connections out of the enclave over vsock, and AWS credentials and API keys are delivered
   over the verifier channel. Optional 2-of-3 Shamir split across the KMS key, a second provider
   and a guardian's age key. Tested with mocks; the live sports test is manual. ✅
6. **End to end.** The whole stack runs locally as deployed: API and enclave-verifier processes,
   Postgres over the wire, KMS over its real protocol with PCR0 policies, drand over HTTP, and
   mock sports providers over TLS. The `condlock` CLI drives it (`device register`,
   `lock --escrow` / `--nfl` / `--guardian`, escrow-aware `unlock`/`status`/`log`). Cheat
   attempts are tests, and each must stay locked. Vault format v2 adds key commitment.
   [DEPLOY.md](DEPLOY.md) has the real AWS steps and costs. ✅

## Core vault format (v2; v1 still readable)

```
<vault>/
  vault.json          public header: format, version, vaultId, chunkSize, kdf, keyCommitment (no names, no sizes)
  manifest.enc        encrypted JSON: entries [{ fileId, name, kind: file|dir, size, sha256 }]
  data/<fileId>.bin   encrypted stream per entry (a folder is one tar stream)
```

Each encrypted stream:

```
header  = "CLK1" | version u8 | fileId 16B | chunkSize u32be          (25 bytes)
record  = nonce 12B (random) | AES-256-GCM(chunk) | tag 16B
AAD     = "condlock/v1/chunk" | header | vaultId 16B | index u64be | final u8
```

**Key commitment (v2, milestone 6).** AES-GCM isn't key-committing. A crafted ciphertext can
authenticate under two keys and decrypt to two different plaintexts: the "invisible
salamanders" attack, and `test/commitment.test.ts` builds one. v2 follows the AWS
Encryption SDK's committing suites and never uses the DEK directly. HKDF-SHA256 (salt = vault
ID) derives two values from it:
- the AES-256-GCM key for the manifest and the streams (info `condlock/v2/aes-256-gcm-key`);
- a 32-byte commitment, stored in `vault.json` as `keyCommitment`, whose info covers the header
  (`condlock/v2/key-commitment` plus format, version, vault ID, chunk size and kdf).

Opening compares the commitment in constant time before reading anything else. A wrong key,
or any edit to `vault.json`, fails with `WrongKeyError`. That includes a downgrade to v1:
the streams were sealed under the derived key, so they fail too. v1 vaults, which use the DEK
directly with no commitment, still open. The stream format below is unchanged (stream header
version 1).

The `final` flag is authenticated, so dropping trailing chunks is detected; every
stream ends with exactly one final record (an empty file is one empty final record).
The manifest uses the same scheme with a reserved all-zero fileId. Decrypted output is
written to a temporary file and only renamed into place after the whole stream
authenticates.

## Timelock envelope (v1, milestone 2)

The DEK is also wrapped with drand timelock encryption (tlock-js) to a future round of
**quicknet** (League of Entropy mainnet, 3 s rounds, `bls-unchained-g1-rfc9380`, chain hash
`52db9ba7…e971`). The chain parameters are pinned in code and stored with each envelope:

```json
{
  "format": "condlock-tlock", "version": 1,
  "vaultId": "<hex>",
  "round": 35330212,
  "unlockAt": "2027-01-01T09:00:00.000Z",
  "chain": { "hash", "publicKey", "period", "genesisTime", "schemeID", "beaconID", "groupHash" },
  "ciphertext": "-----BEGIN AGE ENCRYPTED FILE----- ..."
}
```

- **Sealed payload:** `"CLT1" | vaultId (16 B) | DEK (32 B)`, so an envelope can't be moved to
  another vault.
- **Round for a time:** the earliest round published at or after the target,
  `ceil((t − genesis) / period) + 1`. This is pure arithmetic, so a lock never opens early.
  `unlockAt` is that round's publish time.
- **Wrapping is offline:** only the pinned chain public key is needed.
- **Unwrapping never reads the laptop clock.** tlock-js's `timelockDecrypt` checks `Date.now()`,
  so Condition Lock uses tlock-js's age and IBE modules with its own stanza handler instead.
  That handler:
  1. checks the stanza's round and chain hash against the envelope,
  2. fetches the round's beacon and BLS-verifies it against the pinned public key,
  3. decrypts with tlock-js IBE.

  If the beacon is missing, it asks drand for the latest round. If the latest round is earlier,
  it throws `StillLockedError` ("still locked until <time>"). If drand can't be reached or the
  beacon fails verification, it throws `DrandUnavailableError` (state unknown, never "open").
  Tampering raises `IntegrityError`.
- **Known risk:** if drand stopped publishing, rounds after that point could never be opened.
  The KMS escrow path is the second route.

## CLI (v1, milestone 3)

A locked vault folder (`<input>.condlock` next to the input by default, or `--vault <dir>`):

```
Holiday.condlock/
  vault.json, manifest.enc, data/   from core (milestone 1)
  keys/timelock.json                tlock envelope to the unlock time
  keys/failsafe.json                tlock envelope to the fail-safe date
  lock.json                         condition summary: rounds and times (no names)
  log.jsonl                         local append-only log, hash-chained (no names)
```

**`lock`** does these steps in order. Nothing is deleted unless every step before it succeeded.

1. Validate the inputs. It refuses the filesystem root, the home folder or anything containing
   it, overlapping inputs, a vault inside what it locks, or an existing vault path.
2. Take "now" from drand's latest verified round. If drand can't be reached, fall back to the
   laptop clock with a warning; this is used only to turn durations like `10m` into a target.
3. Work out the unlock and fail-safe rounds. The fail-safe defaults to 1 year (or the unlock
   time, if that is later), must be at least 30 days away, and can't be earlier than the
   unlock time.
4. Show the inputs (with file counts and sizes), the vault path and both times, and require the
   typed word `delete`. `--yes` skips this. If you decline, nothing is created and no key is
   generated.
5. Generate the DEK in memory. Create the vault, wrap both envelopes, write `lock.json`, then run
   `verifyVault`, which decrypts every stream and checks its hash. Zero the DEK. If anything
   fails, remove the partial vault and leave the originals untouched.
6. Log `locked`, delete the originals with `rm` (not moved to the Trash), log
   `originals-deleted`, and print the copies checklist.

**`unlock`** tries the envelopes from the earliest round to the latest.
- If drand has published a round, the vault is restored next to it (or to `--out`). Existing
  files are never overwritten, and the DEK is zeroed.
- If every round is still in the future, it prints `still locked until <time>` with the
  rounds left, and exits 2.
- If drand can't be reached, it exits 3 and changes nothing.

Every attempt is logged.

**`status`** shows the times, rounds and encrypted item count, and how many rounds drand has
left (`--offline` skips the network). It never shows names.

**`log`** prints the entries and verifies the hash chain. Each line holds the SHA-256 of the
line before, so an edited or removed line is reported. Deleting or truncating the whole local
file can't be prevented; the escrow's server-side audit log (milestone 4) covers that.

**Key handling.** The DEK is never written to disk raw. Tests check every vault file for the
key's raw, hex and base64 forms, and check that the key buffer is zeroed after `lock`. WebCrypto
keeps its own internal copy of the imported key, which JavaScript can't wipe; the process exits
right after.

## Escrow service (v1, milestone 4)

**The split.** The API (untrusted host) and the key-release verifier (built to run inside an
AWS Nitro Enclave) talk over one narrow request/response interface (`ReleaseRequest` →
`ReleaseResponse`, length-prefixed JSON). It runs over vsock in production (bridged by socat),
a Unix socket in tests, or in-process for local development.

| | API (parent host) | Verifier (enclave) |
|---|---|---|
| KMS | `Encrypt` only (policy: context `app=condition-lock`) | `Decrypt` only, with Recipient attestation; policy pins PCR0 |
| Holds | Postgres, audit log, device keys, "released once" | nothing: stateless, reads no clock |
| Decides | request auth (Ed25519, ±5 min of server clock, single-use nonce) | whether the sealed terms are met |

**The seal.** `seal = sha256(canonical { v:1, vaultId, condition, failsafeAt })` is part of the
KMS encryption context: `{ app: "condition-lock", vaultId, seal }`. A wrapped key therefore only
decrypts for exactly the terms it was sealed with. Editing the condition or fail-safe in the
database, or copying a wrapped key to another vault, makes KMS refuse.

**Time.** The verifier decides by drand alone. The API passes the latest beacon, and the verifier
BLS-verifies it against the pinned quicknet key. A time-lock is met once the beacon's round is at
least `roundForTime(unlockAt)`, and the fail-safe once it is at least `roundForTime(failsafeAt)`.
The server clock is used only for request freshness and for validating new locks (fail-safe at
least 30 days and at most 10 years away, unlock in the future). NFL conditions: milestone 5.

**Release.** After the verifier approves, a conditional `UPDATE ... WHERE status IN
('sealed','met')` moves the lock to `released` or `failsafe` atomically, so concurrent or repeat
unlocks get `409`. Every request and outcome is audited: `unlock-requested`,
`unlock-denied` (with a reason), `unlock-failed` (with a reason), `released` (with the drand
round). `recordConditionMet` is bookkeeping for milestone 5 jobs; it doesn't release anything.

**Database guards** (`db/migrations/001_init.sql`):
- `audit_log` rejects UPDATE, DELETE and TRUNCATE.
- Lock rows can't be deleted, sealed columns can't change, and status only moves
  `sealed → met → released`, `sealed → released`, or `sealed|met → failsafe`.
- `db/roles.sql` sets up a service role without owner rights, for production.

**Key-wrapping seam.** `KeyWrapper { scheme, wrap(dek, ctx), unwrap(wrapped, ctx) }` plus a
`KeyWrapRegistry` (a primary for new locks; unwrap picks by stored scheme). Implementations are
`AwsKms` (optionally attestation-bound) and `MockKms`/`MockKmsService`/`MockNsm` for tests.
Future layers (post-quantum hybrid, threshold or split-key) plug in as further wrappers.

**Attestation-bound decrypt.** In the enclave, each decrypt generates an ephemeral RSA-2048 key
and gets an NSM attestation document over it. It then calls `Decrypt` with
`Recipient { RSAES_OAEP_SHA_256, AttestationDocument }`, receives `CiphertextForRecipient`
(CMS EnvelopedData: RSAES-OAEP-SHA256 key transport, AES-256-CBC content), and opens it inside
the enclave. The key policy (`services/escrow/enclave/key-policy.json`):
- allows Decrypt only with `kms:RecipientAttestation:PCR0` equal to the image hash;
- denies Decrypt without attestation;
- denies `PutKeyPolicy`, `CreateGrant` and `ReEncrypt*` to everyone, root included (the key is
  created with the lockout-check bypass).

The image is therefore frozen per key; see [ENCLAVE.md](ENCLAVE.md) for the trade-offs and
setup.

**Not done yet:**
- the `nsm-attest` helper binary (a Rust sketch is in ENCLAVE.md);
- end-to-end runs on real Nitro hardware.

Both are manual steps for you. Delivering AWS credentials into the enclave was done in
milestone 5.

## Verifiers, egress and the 2-of-3 split (v1, milestone 5)

**Where conditions are checked.** All checks happen inside the key-release verifier, at unlock
time, and the API host supplies no results. The order:
1. A fail-safe that drand has reached releases the key without asking anyone else.
2. A time condition compares drand rounds.
3. An NFL condition runs `NflChecker`, with "now" taken from the verified drand beacon:
   - **Before kickoff:** not met, and no API calls.
   - **Fetching:** it calls API-Sports and TheSportsDB itself. If either fails:
     `sources-unavailable` (503).
   - **Same game:** both sources must report the sealed teams, and TheSportsDB's
     `idAPIfootball` must match the sealed API-Sports ID.
   - **Agreement:** both must report the same terminal state. If one lags, it waits. If they
     conflict, it stays locked (`sourcesDisagree`).
   - **Final:** scores must be equal. A tie follows `ifTie`; a win or loss for `team` opens the
     lock if it's the sealed `outcome`.
   - **Postponed / cancelled:** they follow `ifPostponed` (`wait` | `unlock` | `stay-locked`)
     and `ifCancelled`.
   - **Resolved outcomes:** if the result can never open the lock, the reply carries
     `resolved: true`, and only the fail-safe opens it.

Every rule is part of the condition, so it's part of the seal and of the KMS context.

**NFL condition (v2 of the shape).** The fields are:
- `game { apiSportsId, theSportsDbId, home, away, kickoffAt }`;
- `team`, `outcome: win | loss`;
- `ifTie`, `ifPostponed`, `ifCancelled`.

This replaces the milestone 4 placeholder (a single `gameId`). No NFL locks were ever issued,
so nothing needed migrating.

**Egress.** The enclave's only way out is vsock.
- `RoutedDialer` maps allowlisted `host:443` names to local ports. Each port goes over socat
  and vsock to `vsock-proxy` on the parent, and from there to the host.
- `EgressHttps` runs TLS inside the verifier, checked against Node's bundled CA roots (part of
  PCR0), with SNI and hostname verification. The parent sees only ciphertext.
- The allowlist itself (`EGRESS_ROUTES`) is baked into the image.
- The AWS SDK uses the same path, through `NodeHttpHandler` with the egress agent.
- Tests run real TLS with a throwaway CA through byte forwarders. They check that the forwarder
  can't read keys or responses, and that a parent presenting its own CA, or a valid certificate
  for another name, is rejected.

**Credentials.** The parent's `startCredentialRelay` pushes `{ op: "secrets", aws, sports }` over
the verifier socket:
- the AWS part is the instance role's short-lived credentials, from the SDK default chain
  (IMDS);
- the sports part is the two API keys.

The `SecretStore` keeps them in memory and feeds the SDK's credential provider and the sports
clients. The relay re-pushes 5 minutes before expiry, at least every 10 minutes, and retries
every 15 seconds after a failure. This grants nothing new: the key policies still require
attestation.

**2-of-3 split** (`ThresholdKeyWrapper`, scheme `shamir-2of3/v1`).
- **Splitting:** `shamir-secret-sharing` (audited) splits the DEK into 3 shares with threshold 2.
- **Holders:**
  - share a: the escrow's KMS key (`KeyWrapper`);
  - share b: a second provider (`KeyWrapper`; mocked, with real options documented);
  - share c: the guardian, as age to their public key. `age-encryption` is the reference
    TypeScript implementation, and X25519 and hybrid post-quantum recipients both work.
- **Binding:** a and b are bound through each provider's context (vault + seal). c's plaintext
  is `"CLG1" | vaultId | seal | share`.
- **Commitment:** `HMAC-SHA256(dek, "condlock/shamir-2of3/v1/commit" | vaultId | seal)` lets
  unwrap pick a pair of shares that rebuilds the right key.
- **Unwrapping:** the verifier tries a and b. With fewer than two, it adds the guardian's share
  from the request; still fewer than two is `insufficient-shares` (503), listing each holder's
  outcome.
- **Old locks:** the single-key wrapper stays registered, so old locks still unwrap. The tlock
  fail-safe is unchanged.

**Known limits.**
- **The API host sees the DEK when a lock is created** (it's sent to `POST /locks`). That was
  true in milestone 4 too. The split and the enclave protect the key at rest and at release,
  not at creation.
- **Collusion:** a guardian who colludes with the second provider's operator can rebuild the
  key, if that provider isn't attestation-bound. That's inherent to "any two".
- **Shares at unlock:** the guardian's decrypted share passes through the API host at unlock
  time. It's one share, bound to one vault and its terms, and both other shares are
  enclave-bound.
- **Real-API checks:** the API-Sports parser follows the documented format and has only been
  checked against mocks. TheSportsDB's matches its live API. The live test checks both with
  your keys.

## End to end and cheat attempts (milestone 6)

**CLI with the escrow.**
- `condlock device register --escrow <url>` creates an Ed25519 device key in
  `$CONDLOCK_HOME/device.json` (mode 600) and registers it with the admin token. Request
  signing is shared code in `@condlock/core`.
- `lock --escrow` (time) and `lock --nfl <file>` (optionally `--guardian age1…`) work as before
  up to `verifyVault`, then `POST /locks` with the DEK. The originals are deleted only after the
  escrow answers 201.
- `lock.json` v2 records the escrow, the key scheme, the condition hash and a copy of
  `vault.json`.
- `unlock` tries the local tlock keys first. If they're still locked, it compares `vault.json`
  with that copy, so a damaged header doesn't spend the one release, and then asks the escrow.
  Exit 5 means the escrow is unavailable or short of shares.

**The local stack** (`e2e/src/stack.ts`), as in DEPLOY.md:

| Deployed piece | Stand-in |
|---|---|
| EC2 parent: escrow API | `src/server.ts` as its own process, `NODE_ENV=test` |
| Nitro Enclave: verifier | `src/verifier/main.ts` as its own process. `nsm-attest` is a mock helper signing for a chosen PCR0 |
| `vsock-proxy` per host | byte forwarders |
| AWS KMS | a mock speaking AWS JSON 1.1 (Encrypt/Decrypt, Recipient → CiphertextForRecipient), PCR0 key policies |
| Neon Postgres | PGlite behind a Postgres wire-protocol socket, through node-postgres |
| drand quicknet | a private chain served over drand's HTTP API (tests publish rounds) |
| API-Sports, TheSportsDB | mock HTTPS servers (throwaway CA) |

The test-only hooks are refused when `NODE_ENV=production`, and a test checks this. They are
`DRAND_CHAIN_FILE`, `EGRESS_EXTRA_CA_FILE` and `DEV_NO_ATTESTATION`.

**Cheat attempts** (`e2e/test/cheats.test.ts`). Each must leave nothing restored and the escrow
lock unreleased:

| Attempt | What stops it |
|---|---|
| Device clock days ahead or behind | tlock ignores the clock; the escrow rejects the stale signature (logged) |
| Edit or delete the local log | the hash chain reports it; nothing depends on the log |
| Edit, delete or truncate the server log | append-only triggers. The service role can't drop or disable them. Even the DB owner wiping rows unlocks nothing |
| Replay, forge, re-path or body-swap a signed request; stale timestamp; unknown device | single-use nonces, Ed25519 over method, path, time, nonce and body hash; all logged |
| Edit `lock.json` or a tlock key's round | the round is inside the tlock ciphertext |
| DB owner rewrites the sealed condition, or moves a wrapped key to another vault | the seal and the vault ID are in the KMS encryption context: `unwrap-failed` |
| Non-approved enclave image with the parent's credentials | the KMS key policy needs the approved PCR0: `access-denied` |
| API host calls KMS Decrypt directly | no attestation: `AccessDeniedException` |
| One source lies about the score; sources disagree on final vs postponed; a wrong game link; one still in Q4 | two-source agreement: stays locked, `sourcesDisagree` logged with both reports |
| A source or KMS down; a source unreachable at the network level | `sources-unavailable` or `key-service`, 503: try later, never a release |
| Only one 2-of-3 share (either provider, or the guardian), or the guardian's share before the time | Shamir needs two shares, and the condition is checked first |
| Tampered `vault.json` | the CLI won't ask the escrow, and the key commitment refuses it. Editing both copies spends the release but restores nothing |

**Known limits** (unchanged from earlier milestones unless noted):
- **The escrow sees the DEK when a lock is created.**
- **Editing the header in both places:** if you edit `vault.json` and its copy in `lock.json`,
  the one escrow release is spent. Restore `vault.json` and the tlock keys still open the vault
  (new in milestone 6).
- **The database owner** can disable the triggers and rewrite history. That can't unlock
  anything, but the server log is only as trustworthy as the owner. The service role can't do
  it.
- **The CLI holds the DEK as a base64 string** in the `POST /locks` body for a moment. JS
  strings can't be zeroed.
