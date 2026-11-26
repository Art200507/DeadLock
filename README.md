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
                         └─► DEK wrapped by AWS KMS in the escrow   ── opens when a verifier records the
                                                                       condition as met (NFL result, time)
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
3. **KMS escrow** (`services/escrow`, planned): a small Hono API with no "release" button.
   Verifiers check conditions on a schedule. Unlock returns the KMS-unwrapped DEK once, to a
   registered device key, and every check and request goes in an append-only audit log.

## Status

| # | Milestone | Status |
|---|-----------|--------|
| 1 | Core crypto: chunked AES-256-GCM, encrypted manifest, tar for folders | ✅ done |
| 2 | tlock: wrap/unwrap the DEK on drand quicknet, round-for-time math | ✅ done |
| 3 | CLI, local only: `condlock lock / unlock` with tlock fail-safe, shredding, copies checklist | ⏳ next |
| 4 | Escrow service: Hono API, Postgres migrations, AWS KMS, device signatures, audit log | planned |
| 5 | Verifiers: time (server clock + drand) and NFL (API-Sports + TheSportsDB must agree) | planned |
| 6 | End to end against the deployed escrow, including cheat attempts | planned |

## Repo layout

```
packages/core      crypto: chunked AES-256-GCM vault, manifest, tlock wrap/unwrap
packages/cli       condlock lock | unlock | status | log          (stub)
services/escrow    Hono API, verifiers, KMS + Postgres adapters   (stub)
db/migrations      locks, devices, audit_log                      (stub)
docs/DESIGN.md     design summary, vault and envelope formats
```

## Running the tests

Requires Node 22+ and pnpm (`corepack enable`, or prefix commands with `npx pnpm@10`).

```sh
pnpm install
pnpm typecheck
pnpm test                                   # everything, including real drand (~1 min)
pnpm --filter @condlock/core test:offline   # skip network tests (CONDLOCK_OFFLINE=1)
```

The network tests talk to the public drand quicknet. One locks a key for one minute, checks it
reports "still locked until <time>", and polls drand until it opens. The offline suite uses a
mocked drand network that signs real BLS beacons with a throwaway key.

## Secrets

Cloud accounts and API keys (AWS, Neon/Supabase, API-Sports, TheSportsDB) are read from a `.env`
file that is git-ignored and never committed. No keys live in this repo.
