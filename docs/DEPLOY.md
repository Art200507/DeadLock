# Deploying Condition Lock to AWS

> **Status: a plan for you to run. Nothing here has been created or paid for.** Every step
> below runs in *your* accounts. The local end-to-end suite (`pnpm --filter @condlock/e2e test`)
> runs this same layout with stand-ins for each cloud piece. Prices are us-east-1 list prices
> from late 2026 (sources at the end). Check them before you start, and tear down what you don't
> use.

## What gets deployed

```
 condlock CLI ──HTTPS──► Caddy (TLS, :443) ──► escrow API (Node, :8787) ──► Neon Postgres
 (your laptop)            on one EC2 Graviton instance with Nitro Enclaves enabled
                                         │ Unix socket ─ socat ─ vsock :5005
                                         ▼
                            Nitro Enclave: key-release verifier
                              egress via vsock-proxy (allowlist) to
                              KMS · API-Sports · TheSportsDB
 KMS key A (this account)  ── Decrypt only for the attested enclave image (PCR0)
 KMS key B (second account, optional 2-of-3) ── same policy, different owner
 drand quicknet (public) ── time evidence for CLI, API and verifier
```

The design doc assumed a serverless API at about $1 a month. Moving key release into a Nitro
Enclave needs an always-on EC2 instance, and that instance is almost the whole bill (see
"Monthly cost" below).

## 0. Before you start

You'll need:
- An AWS account you control, with the AWS CLI v2. Optionally, a **second AWS account owned by
  someone else** for share b of 2-of-3 locks.
- A [Neon](https://neon.com) account (the free plan is enough).
- An API-Sports key (free plan: 100 requests a day) and a TheSportsDB key (`123` is their
  public free key; $9 a month gets a production key).
- A domain name for the escrow's HTTPS endpoint, e.g. `escrow.example.com`.
- On your laptop: this repo, Node 22, `pnpm` (or `npx pnpm@10`), and a Rust toolchain for the
  `nsm-attest` helper.

Keep every secret in a password manager or AWS Secrets Manager, never in the repo. This
includes the Neon URLs, the admin token, the API keys and the KMS key ARNs.

## 1. Database (Neon)

1. Create a project in the region nearest your instance (e.g. AWS us-east-1). Copy the
   **owner** connection string (`postgres://neondb_owner:…@…/neondb?sslmode=require`).
2. Apply the schema, as the owner:
   ```sh
   cd services/escrow
   DATABASE_URL='<owner url>' pnpm migrate          # → applied: 001_init.sql
   ```
3. Create the service role. Copy `db/roles.sql` somewhere outside the repo and replace
   `CHANGE_ME` with a strong password (`openssl rand -base64 30`). Then run it as the owner:
   ```sh
   psql '<owner url>' -f /path/to/your-roles.sql
   ```
   The API will connect as `condlock_app`. That role can't alter the schema, drop the
   triggers, or edit or delete audit rows (the e2e suite checks this). Its URL is the owner URL
   with `condlock_app:<password>`.

Notes:
- **Neon's free plan:** 1 GB of storage and 100 compute-hours a month per project, and the
  compute sleeps after 5 minutes idle. A lock row is about 1 KB, so the limits are far away.
  The first request after a sleep takes a few hundred milliseconds longer.
- **Supabase:** it works the same way, but free projects are paused after a period of
  inactivity. Check their current policy before relying on it for an escrow.

## 2. IAM roles

Create these in the escrow account:

- **`condlock-escrow-instance`** (EC2 instance profile). Inline policy, with your key ARNs:
  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"],
        "Resource": ["arn:aws:kms:us-east-1:ACCOUNT_ID:key/KEY_A_ID", "arn:aws:kms:us-east-1:SECOND_ACCOUNT_ID:key/KEY_B_ID"]
      }
    ]
  }
  ```
  The IAM side may say Decrypt, but each **key policy** still only allows it with the
  enclave's attestation (step 4).
- **`condlock-key-auditor`**: no permissions of its own. The key policy gives it read-only
  access plus key deletion.

Add `AmazonSSMManagedInstanceCore` to the instance role if you want Session Manager instead of
SSH. Then you can keep port 22 closed.

## 3. The instance

1. **Launch the instance:** a `c6g.xlarge` (Graviton, 4 vCPU, 8 GiB) running Amazon Linux 2023
   arm64, with enclaves enabled. The ENCLAVE.md step 1 command works if you change the
   instance type and AMI. Give it a 20 GB gp3 root volume. The security group allows inbound
   443 from anywhere and 22 only from your IP (or nothing, with SSM).
2. **Point DNS at it:** attach an Elastic IP, and point `escrow.example.com` at it with an A
   record.
3. **Install the tools** on the instance:
   ```sh
   sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker socat git nodejs22 caddy
   ```
   If `caddy` or `nodejs22` isn't in the AL2023 repos, install Caddy from caddyserver.com and Node 22 from nodejs.org.
4. **Allocate the enclave:** 2 vCPUs and 2 GiB, as in ENCLAVE.md step 1.

Graviton is about 20% cheaper than the Intel equivalent (`c6i.xlarge`). It means an arm64
enclave image: the base image is multi-arch, and you build `nsm-attest` for
`aarch64-unknown-linux-musl`.

## 4. Enclave image, PCR0, KMS keys

Follow [ENCLAVE.md](ENCLAVE.md) steps 2–4b exactly:
1. Fill in `REPLACE_REGION` (in `AWS_REGION` and `EGRESS_ROUTES`) and the pinned base-image
   digest in `services/escrow/enclave/Dockerfile`. Then build the image and the EIF, and record
   **PCR0**.
2. Create **key A** with `enclave/key-policy.json` (PCR0 pinned, `PutKeyPolicy` denied to
   everyone) using `--bypass-policy-lockout-safety-check`.
3. Optional 2-of-3: the second account's owner creates **key B** with
   `enclave/second-provider-key-policy.json` and gives you its ARN.

Keep the `.eif` file and its PCR0 next to the key ARNs. Both keys work only with that exact
image.

## 5. Services (systemd)

Put the API's environment in `/etc/condlock/escrow.env` (`chmod 600`, owned by root):

```sh
NODE_ENV=production
PORT=8787
HOST=127.0.0.1
DATABASE_URL=postgres://condlock_app:<password>@<neon-host>/neondb?sslmode=require
SKIP_MIGRATIONS=1
KMS_PROVIDER=aws
KMS_KEY_ID=arn:aws:kms:us-east-1:ACCOUNT_ID:key/KEY_A_ID
AWS_REGION=us-east-1
# 2-of-3 (optional):
# KEY_SPLIT=2of3
# SECOND_PROVIDER=aws
# SECOND_KMS_KEY_ID=arn:aws:kms:us-east-1:SECOND_ACCOUNT_ID:key/KEY_B_ID
VERIFIER_SOCKET=/run/condlock/verifier.sock
CREDENTIAL_RELAY=1
APISPORTS_KEY=<your key>
THESPORTSDB_KEY=<your key or 123>
ESCROW_ADMIN_TOKEN=<openssl rand -hex 32>   # remove after registering your devices (step 6)
```

Then the units, sketched. Adjust the paths to where you cloned and built the repo
(`pnpm install --frozen-lockfile && pnpm -r build`):

```ini
# /etc/systemd/system/condlock-proxies.service: egress for the enclave
[Service]
ExecStart=/bin/sh -c 'vsock-proxy 8000 kms.us-east-1.amazonaws.com 443 & \
  vsock-proxy 8001 v1.american-football.api-sports.io 443 --config /etc/nitro_enclaves/vsock-proxy.yaml & \
  vsock-proxy 8002 www.thesportsdb.com 443 --config /etc/nitro_enclaves/vsock-proxy.yaml & wait'
Restart=always

# /etc/systemd/system/condlock-enclave.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/nitro-cli run-enclave --eif-path /opt/condlock/condlock-verifier-v1.eif --cpu-count 2 --memory 2048 --enclave-cid 16
ExecStop=/usr/bin/nitro-cli terminate-enclave --all

# /etc/systemd/system/condlock-bridge.service: API's Unix socket ↔ enclave vsock 5005
[Service]
RuntimeDirectory=condlock
ExecStart=/usr/bin/socat UNIX-LISTEN:/run/condlock/verifier.sock,fork,mode=600 VSOCK-CONNECT:16:5005
Restart=always

# /etc/systemd/system/condlock-escrow.service
[Unit]
After=condlock-bridge.service condlock-enclave.service
[Service]
EnvironmentFile=/etc/condlock/escrow.env
WorkingDirectory=/opt/condlock/repo/services/escrow
ExecStart=/usr/bin/node dist/server.js
Restart=always
User=condlock
```

Add the two sports hosts to `/etc/nitro_enclaves/vsock-proxy.yaml` (ENCLAVE.md step 5). The
API process's start-up log should say
`delivered aws, sports to the verifier`.

**HTTPS:** `/etc/caddy/Caddyfile`:
```
escrow.example.com {
  reverse_proxy 127.0.0.1:8787
}
```
Caddy gets and renews a Let's Encrypt certificate by itself. The CLI refuses plain `http://`
for anything but localhost.

## 6. Register your devices, then close registration

On your laptop:
```sh
CONDLOCK_ADMIN_TOKEN=<the token> condlock device register --escrow https://escrow.example.com --label laptop
```
Then delete `ESCROW_ADMIN_TOKEN` from `escrow.env` and restart the API. `POST /devices` returns
404 from then on, so nobody can add a device without editing the server.

## 7. Check it end to end (the design doc's phase-1 "done")

1. **Time-lock:** `condlock lock ./test-folder --until 10m --escrow`. Until the time:
   - `condlock unlock` says still locked;
   - changing your laptop clock doesn't help (the escrow rejects the stale signature);
   - editing the lock row in Neon doesn't help (`unwrap-failed`).

   After the time it opens, and `condlock log --server` shows every attempt.
2. **NFL:** write a condition file for a real upcoming Bills game. Get the two IDs from
   API-Sports `games?date=` and TheSportsDB `eventsday.php`; see `services/escrow/README.md`.
   Lock a test folder with `--nfl`. It stays locked before and during the game and opens after
   a win. A loss shows `resolved` and waits for the fail-safe.
3. **Enclave checks:** run ENCLAVE.md "Checks" 2–4. Those cover a direct KMS Decrypt from the
   parent, a debug-mode enclave and a changed image, and each must be refused.
4. **Optional:** run `pnpm --filter @condlock/escrow test:live-sports` with your keys first, to
   confirm both providers parse.

## 8. Operating it

- **Updates** to the verifier code change PCR0. That needs a new key (step 4) and, for new
  locks, the new key ID in `escrow.env`. Keep the old EIF available for old locks (see the
  ENCLAVE.md trade-offs).
- **Backups:** Neon keeps restore history (the window depends on the plan). The vaults
  themselves live on your laptop, with their tlock fail-safe keys inside.
- **Logs:** journald on the instance. CloudWatch Logs is optional (5 GB a month is in the free
  tier).

## Monthly cost (us-east-1, list prices, 730 hours)

| Item | Choice | $/month |
|---|---|---|
| EC2 | c6g.xlarge on-demand, $0.136/h | 99.28 |
| EBS | 20 GB gp3, about $0.08/GB-month | 1.60 |
| Public IPv4 | 1 Elastic IP, $0.005/h (750 h/month free for 12 months on the EC2 free tier) | 3.65 |
| KMS keys | key A $1; key B $1 (billed to the second account) | 1.00 (+1.00) |
| KMS requests | about 2 per lock and about 2 per unlock; 20,000 free a month | 0.00 |
| Neon | free plan | 0.00 |
| Sports data | API-Sports free (100/day); TheSportsDB free key | 0.00 |
| DNS | Route 53 hosted zone ($0.50) + a domain (about $13/yr) | about 1.60 |
| Data transfer | well under the 100 GB/month free allowance | 0.00 |
| **Total** | | **≈ $107** (≈ $108 with key B) |

Ways to pay less:
- **1-year Compute Savings Plan** (no upfront): c6g.xlarge drops to about $0.086/h, so
  **≈ $70/month** in total.
- **c6g.large** (2 vCPU): AWS lists 2 vCPUs as the Graviton minimum for enclaves, which leaves
  one vCPU for the enclave and one for the parent. That's about $50 for the instance, so
  **≈ $57/month**. I haven't confirmed that the verifier runs well on one vCPU; try it before
  committing.
- **Stop the instance between unlocks.** Locks live in Neon and the vaults on your laptop, so
  you only need it running to lock or unlock. Stopped, you pay EBS, the IP and the keys:
  **≈ $8/month** plus about $0.14 per hour it runs. The enclave and its PCR0 are unchanged
  after a restart.
- **Paid tiers you might add:** API-Sports from about $15 a month, TheSportsDB $9 a month, Neon
  Launch if you outgrow the free plan.

Spot instances are cheaper, but they can be reclaimed at any moment. That's acceptable for an
escrow only if you're fine with unlocks sometimes waiting.

## Teardown

Terminate the instance and release the Elastic IP. As the auditor role, schedule the KMS
key(s) for deletion, after reading the deletion note in ENCLAVE.md: deleting a key removes the
escrow route for every lock under it, and only the tlock fail-safes remain. Delete the Neon
project and the DNS records.

## Sources

- EC2 instance prices (c6g/c6i, us-east-1), via aggregators:
  [Vantage c6i.xlarge](https://instances.vantage.sh/aws/ec2/c6i.xlarge),
  [Holori c6g.xlarge](https://www.calculator.holori.com/aws/ec2/c6g.xlarge?region=us-east-1),
  [Economize c6g.xlarge](https://www.economize.cloud/resources/aws/pricing/ec2/c6g.xlarge/).
  Confirm on [AWS EC2 on-demand pricing](https://aws.amazon.com/ec2/pricing/on-demand/).
- [Nitro Enclaves requirements](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)
- [Public IPv4 charge](https://aws.amazon.com/blogs/aws/new-aws-public-ipv4-address-charge-public-ip-insights/),
  [free tier for public IPv4](https://aws.amazon.com/de/about-aws/whats-new/2024/02/aws-free-tier-750-hours-free-public-ipv4-addresses/)
- [EBS pricing](https://aws.amazon.com/ebs/pricing), [KMS pricing](https://aws.amazon.com/kms/pricing/)
- [Neon plans](https://neon.com/pricing), [Neon free plan limits](https://neon.com/faqs/free-plan-limits-and-quotas)
