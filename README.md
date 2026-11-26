# Condition Lock

Encrypt files locally; the only key lives in a cloud escrow that releases it when a
sealed condition is met (a time, or an NFL result). See [docs/DESIGN.md](docs/DESIGN.md).

```
packages/core      crypto: chunked AES-256-GCM, encrypted manifest   (milestone 1 ✅)
packages/cli       condlock lock | unlock | status | log             (milestone 3)
services/escrow    Hono API, verifiers, KMS + Postgres adapters      (milestones 4–5)
db/migrations      locks, devices, audit_log                         (milestone 4)
```

Requires Node 22+ and pnpm (`corepack enable` or `npx pnpm@10`).

```
pnpm install
pnpm test
```

Secrets (AWS, database, sports API keys) are read from a `.env` file that is never committed.
