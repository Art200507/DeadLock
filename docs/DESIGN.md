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
2. tlock wrap/unwrap of the DEK on drand quicknet.
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
