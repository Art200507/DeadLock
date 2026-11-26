# Condition Lock

Condition Lock is a commitment device for files. It encrypts files on your laptop, removes
the originals, and keeps the only key somewhere you can't reach alone. The key comes back only
when a sealed condition is verified true: a set time, or an NFL result. Every vault also has a
fail-safe date, so nothing is lost forever.

📄 **Design doc:** https://claude.ai/artifact/6hcU82mXDqALEXWDSzxmNe (summary and formats in
[docs/DESIGN.md](docs/DESIGN.md))

## How the layers work

```
 your files ──► AES-256-GCM vault (local)       key = random 256-bit DEK per vault
                         │
                         ├─► DEK wrapped by drand timelock (tlock)  ── opens when a drand round is published
                         │                                             (time-locks + every vault's fail-safe)
                         └─► DEK held by the escrow                 ── released once by the enclave verifier
                               single KMS key, or a 2-of-3 split:         when the sealed condition is met
                               KMS · second provider · guardian (age)     (drand time, or NFL: two sources agree)
```

1. **AES-256-GCM vault** (`packages/core`): files are streamed in 1 MiB chunks. Each chunk is
   sealed with a unique random nonce. Its associated data covers the vault ID, file ID, chunk
   index and a last-chunk flag, so chunks can't be swapped, reordered, moved or truncated.
   Names and sizes live only in an encrypted manifest. Folders are packed to tar first; any
   file type is opaque bytes. All of this uses Node WebCrypto, with no custom crypto.
2. **drand timelock** (`packages/core`): the DEK is encrypted with
   [tlock-js](https://github.com/drand/tlock-js) to a future round of drand's quicknet. Nobody
   can open it before the League of Entropy publishes that round, including the server and the
   owner. Unlock is decided only by whether drand has published the round; the laptop clock is
   never consulted.
3. **KMS escrow** (`services/escrow`): a Hono API with no "release" button, Ed25519
   device-signed requests, Postgres, and an append-only audit log. The API host can only
   *encrypt*. Releasing a key is done by a separate **verifier**, built to run in an AWS Nitro
   Enclave. It checks the sealed terms against a BLS-verified drand beacon, then calls KMS
   Decrypt with an attestation-bound Recipient. A key policy pinned to the enclave image's PCR0
   means nothing else can decrypt, and the key is released once. See
   [services/escrow/README.md](services/escrow/README.md) and [docs/ENCLAVE.md](docs/ENCLAVE.md).
4. **Verifiers** (`services/escrow/src/verifiers`): time comes from drand alone. NFL results
   are fetched by the verifier itself from API-Sports and TheSportsDB, over TLS that terminates
   inside the enclave. Both sources must agree, and ties, postponements and cancellations follow
   the lock's sealed rules. The parent host relays bytes it can't read or forge, and it
   delivers the enclave's AWS credentials and API keys over the same verifier channel.
5. **2-of-3 key split** (optional): the DEK is split with an audited Shamir library into shares
   held by the enclave-bound KMS key, a second independent provider, and a trusted person's age
   key. Any two release it, and no single account can. The tlock fail-safe stays as it is.

## Status

| # | Milestone | Status |
|---|-----------|--------|
| 1 | Core crypto: chunked AES-256-GCM, encrypted manifest, tar for folders | ✅ done |
| 2 | tlock: wrap/unwrap the DEK on drand quicknet, round-for-time math | ✅ done |
| 3 | CLI, local only: `condlock lock / unlock / status / log` with tlock fail-safe, deletion, copies checklist | ✅ done |
| 4 | Escrow service: Hono API, Postgres, KMS envelope wrapping, device signatures, audit log, enclave-ready verifier | ✅ done (mocks; real KMS and enclave are manual) |
| 5 | Verifiers (time via drand; NFL with API-Sports + TheSportsDB agreeing), TLS egress from the enclave, credential delivery, 2-of-3 key split | ✅ done (mocks; live sports test, real KMS and enclave are manual) |
| 6 | End to end against the deployed escrow, including cheat attempts | ⏳ next |

## Using the CLI

```sh
pnpm install && pnpm build
alias condlock="node $PWD/packages/cli/dist/index.js"

condlock lock ~/Pictures/Holiday --until 2d              # or 10m, 1h30m, 2027-01-01T09:00Z
condlock status ~/Pictures/Holiday.condlock
condlock unlock ~/Pictures/Holiday.condlock              # "still locked until <time>" until drand says so
condlock log ~/Pictures/Holiday.condlock
```

`lock` lists exactly what it will delete and asks you to type `delete` (`--yes` skips this,
for scripts and tests). It then encrypts, writes a tlock key to the unlock time and a
**fail-safe** tlock key (default 1 year, minimum 30 days, `--failsafe <time|duration>`), and
decrypts the whole vault once to prove it opens. Only then does it delete the originals and
print a checklist of places copies may still live (iCloud Photos, Google Photos, Time Machine,
Downloads, chat apps). The data key exists only in memory and is zeroed after use. `unlock`
asks drand, never the laptop clock.

Exit codes: `0` ok · `1` error · `2` still locked · `3` drand unreachable (state unknown) ·
`4` cancelled at the confirmation.

> Milestone 3 is local only: a vault opens at its time through drand. The KMS escrow and
> event conditions (NFL results) arrive in milestones 4 and 5.

## Repo layout

```
packages/core      crypto: chunked AES-256-GCM vault, manifest, tlock wrap/unwrap
packages/cli       condlock lock | unlock | status | log (local, tlock only)
services/escrow    Hono API, key-release verifier (enclave-ready), NFL verifier, TLS egress,
                   KMS + 2-of-3 split + Postgres adapters
db/migrations      locks, devices, audit_log, request_nonces + guard triggers
docs/DESIGN.md     design summary, vault and envelope formats
docs/ENCLAVE.md    Nitro Enclave + KMS key policy setup (manual runbook)
```

## Running the tests

Requires Node 22+ and pnpm (`corepack enable`, or prefix commands with `npx pnpm@10`).

```sh
pnpm install
pnpm typecheck
pnpm test                                   # everything, including real drand (~2 min)
pnpm -r test:offline                        # skip network tests (CONDLOCK_OFFLINE=1)
pnpm --filter @condlock/escrow test:real-kms      # manual: real AWS KMS, see services/escrow/README.md
pnpm --filter @condlock/escrow test:live-sports   # manual: real API-Sports + TheSportsDB free tiers
```

The network tests talk to the public drand quicknet. One in `core` and one in `cli` lock for one
minute, check it reports "still locked until <time>", and poll drand until it opens; the CLI
one restores a mixed folder (photo, PDF, video) and compares it byte for byte. Every CLI test
works inside its own temp directory. The offline suite uses a
mocked drand network that signs real BLS beacons with a throwaway key.

The escrow tests run against:
- PGlite (real Postgres in WASM);
- a mock KMS with a PCR0 key policy, and a mock Nitro attestation;
- a mocked drand network and a real Unix socket;
- mock sports and KMS HTTPS servers, with certificates from a throwaway in-memory CA, reached
  through byte forwarders.

They need no cloud account and no network. The real-KMS and live-sports tests are manual, and
skipped unless you configure your own keys.

## Secrets

Cloud accounts and API keys (AWS, Neon/Supabase, API-Sports, TheSportsDB) are read from a `.env`
file that is git-ignored and never committed (`services/escrow/.env.example` lists the
variables). No keys live in this repo.
