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
  device key. Append-only audit log.
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
3. CLI, local only (lock, tlock fail-safe, shred, copies checklist, unlock via tlock).
4. Escrow service (Hono, migrations, KMS, device signatures, audit log).
5. Verifiers (time, nfl) on a 15-minute schedule.
6. End to end against the deployed escrow, including cheat attempts.

## Core vault format (v1)

```
<vault>/
  vault.json          public header: format, version, vaultId, chunkSize (no names, no sizes)
  manifest.enc        encrypted JSON: entries [{ fileId, name, kind: file|dir, size, sha256 }]
  data/<fileId>.bin   encrypted stream per entry (a folder is one tar stream)
```

Each encrypted stream:

```
header  = "CLK1" | version u8 | fileId 16B | chunkSize u32be          (25 bytes)
record  = nonce 12B (random) | AES-256-GCM(chunk) | tag 16B
AAD     = "condlock/v1/chunk" | header | vaultId 16B | index u64be | final u8
```

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
