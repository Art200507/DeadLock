# Running the key-release verifier in an AWS Nitro Enclave

> **Status: a runbook for you to follow later. Nothing here has been run.** The code is
> enclave-ready and tested against mocks: a mock KMS key policy on PCR0, a mock attestation
> document, and a real CMS `CiphertextForRecipient`. The steps below create real AWS resources
> that cost money (an EC2 instance billed per hour, and a KMS key at about $1/month). Check
> current AWS pricing and tear everything down when you're done.

## Why

Without an enclave, whoever controls the escrow's cloud account can call `kms:Decrypt` and
release any key early (the "admin problem" in the design doc). With this setup:

- the KMS key policy allows `kms:Decrypt` **only** with a Recipient attestation document whose
  `PCR0` equals the hash of one specific verifier image;
- the policy denies `kms:PutKeyPolicy` to everyone, root included, so that rule can't be loosened;
- the verifier inside the enclave releases a key only when the sealed terms are met. It
  recomputes the seal and checks time with a BLS-verified drand beacon, and it reads no clock
  and trusts nothing from the parent host;
- KMS returns the key encrypted to the enclave's ephemeral RSA key (`CiphertextForRecipient`),
  so the parent instance only ever relays ciphertext.

```
 ┌──────────────── EC2 parent instance (untrusted) ─────────────────┐
 │  API (Hono) ── Unix socket ── socat ──┐                            │
 │                                       │ vsock :5005                │
 │  vsock-proxy :8000 ─────────── kms.<region>.amazonaws.com:443      │
 │        ▲                              │                            │
 │ ┌──────┼──────── Nitro Enclave ───────▼─────────────────────────┐  │
 │ │ socat 127.0.0.1:443 → vsock 3:8000    verifier (node)           │ │
 │ │ TLS to KMS terminates HERE            ├─ checks seal + drand    │ │
 │ │                                       ├─ /dev/nsm → attestation │ │
 │ │                                       └─ KMS Decrypt(Recipient) │ │
 │ └─────────────────────────────────────────────────────────────────┘ │
 └────────────────────────────────────────────────────────────────────┘
```

The API host can still `kms:Encrypt` (sealing new locks), refuse service, or delete things;
the tlock fail-safe covers those cases. What it can't do is decrypt a stored key.

## 0. Prerequisites

- An AWS account you control, the AWS CLI v2 configured for it, and a region (say `us-east-1`).
- Two IAM roles you create:
  - `condlock-escrow-instance`: the EC2 instance profile role. The API's Encrypt and the
    enclave's Decrypt both use its credentials.
  - `condlock-key-auditor`: read-only key access plus `ScheduleKeyDeletion`.
- A Rust toolchain to build the small `nsm-attest` helper (step 3).

## 1. Launch an enclave-enabled EC2 instance

Enclaves need a Nitro instance with enough vCPUs to give at least 2 to the enclave, e.g. `c6i.xlarge`
or `m6i.xlarge` (x86), or `c6g.xlarge` (Graviton). Use Amazon Linux 2023.

```sh
aws ec2 run-instances \
  --image-id <al2023-ami-id> --instance-type c6i.xlarge \
  --iam-instance-profile Name=condlock-escrow-instance \
  --enclave-options 'Enabled=true' \
  --key-name <your-ssh-key> --subnet-id <subnet> --security-group-ids <sg>
```

On the instance:

```sh
sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker socat git
sudo usermod -aG ne,docker ec2-user && newgrp ne
# Give the enclave 2 vCPUs and 2 GiB:
sudo sed -i 's/^memory_mib:.*/memory_mib: 2048/; s/^cpu_count:.*/cpu_count: 2/' /etc/nitro_enclaves/allocator.yaml
sudo systemctl enable --now nitro-enclaves-allocator.service docker
```

## 2. Build the verifier image and read its PCRs

```sh
git clone https://github.com/Art200507/DeadLock condition-lock && cd condition-lock
corepack enable && pnpm install --frozen-lockfile && pnpm -r build
pnpm --filter @condlock/escrow deploy --prod services/escrow/enclave/build/app
# Put the nsm-attest binary from step 3 at services/escrow/enclave/nsm-attest, then
# fill in the pinned base-image digest and REPLACE_REGION in the Dockerfile.
docker build -f services/escrow/enclave/Dockerfile -t condlock-verifier:v1 .
nitro-cli build-enclave --docker-uri condlock-verifier:v1 --output-file condlock-verifier-v1.eif
```

`build-enclave` prints the measurements:

```json
{ "Measurements": { "HashAlgorithm": "Sha384 { ... }", "PCR0": "<96 hex chars>", "PCR1": "...", "PCR2": "..." } }
```

**PCR0** is the hash of the whole enclave image; that's the value the key policy pins. PCR1 is
the kernel and boot ramdisk, and PCR2 is the application. `nitro-cli describe-eif --eif-path
condlock-verifier-v1.eif` prints them again. Any change to the code, the lockfile, the base image
or the helper gives a new PCR0, so keep the `.eif` and record its PCR0 next to the key ARN.

A debug-mode enclave (`--debug-mode`) reports PCRs of all zeros, so it can never satisfy the
policy. Never use debug mode for the real key.

## 3. The `nsm-attest` helper

The verifier gets attestation documents by running a helper (`NSM_ATTEST_COMMAND`). The helper
reads the ephemeral public key (SPKI DER) on stdin and writes the raw attestation document to
stdout. Node can't talk to `/dev/nsm` directly. A minimal Rust version using AWS's
[`aws-nitro-enclaves-nsm-api`](https://github.com/aws/aws-nitro-enclaves-nsm-api) crate:

```rust
// Cargo: aws-nitro-enclaves-nsm-api = "0.4", serde_bytes = "0.11"
use aws_nitro_enclaves_nsm_api::{api::{Request, Response}, driver};
use std::io::{Read, Write};
fn main() {
    let mut pk = Vec::new();
    std::io::stdin().read_to_end(&mut pk).unwrap();
    let fd = driver::nsm_init();
    let req = Request::Attestation { public_key: Some(pk.into()), user_data: None, nonce: None };
    match driver::nsm_process_request(fd, req) {
        Response::Attestation { document } => std::io::stdout().write_all(&document).unwrap(),
        other => { eprintln!("nsm error: {:?}", other); std::process::exit(1) }
    }
    driver::nsm_exit(fd);
}
```

Build it statically (`--target x86_64-unknown-linux-musl`), commit its source and lockfile
somewhere reproducible, and copy the binary to `services/escrow/enclave/nsm-attest`.

**Invariant:** the verifier only ever attests to key pairs it generated itself. Never add a
code path that attests to a caller-supplied public key. That would let the parent obtain a
CiphertextForRecipient it can open.

## 4. Create the KMS key with the locked-down policy

Edit `services/escrow/enclave/key-policy.json`: set `ACCOUNT_ID`, the two role names, and
`PCR0_HEX_FROM_NITRO_CLI_BUILD`. What it does:

| Statement | Effect |
|---|---|
| `EscrowMayEncryptForConditionLock` | the instance role may `Encrypt`, only with `EncryptionContext.app = condition-lock` |
| `OnlyTheAttestedEnclaveImageMayDecrypt` | the instance role may `Decrypt` only when `kms:RecipientAttestation:PCR0` matches |
| `EscrowMayDescribeKey` | metadata only |
| `AuditorReadOnlyAndKeyRetirement` | read the policy and grants, schedule or cancel deletion |
| `NobodyMayChangeThisPolicyOrRouteAroundTheEnclave` | **Deny to `*`**: `PutKeyPolicy`, `CreateGrant`, `ReEncrypt*`, `GenerateDataKey*`, `ImportKeyMaterial`, `UpdateKeyDescription` |
| `DenyDecryptWithoutEnclaveAttestation` | **Deny** `Decrypt` whenever there's no attestation |

The account root (`arn:aws:iam::ACCOUNT_ID:root`) is deliberately **not** in the policy, so IAM
policies, even an administrator's, can't grant anything on this key. Because the policy would
lock everyone out of changing it, KMS requires the lockout-check bypass flag:

```sh
aws kms create-key \
  --description "condition-lock enclave key v1 (PCR0 <first 12 hex>)" \
  --key-usage ENCRYPT_DECRYPT --key-spec SYMMETRIC_DEFAULT \
  --policy file://services/escrow/enclave/key-policy.json \
  --bypass-policy-lockout-safety-check
```

Record the key ARN. Use the ARN everywhere: the policy grants no `CreateAlias`, so you can't
create an alias for this key.

Check it:

```sh
aws kms get-key-policy --key-id <arn> --policy-name default        # as the auditor role
aws kms put-key-policy --key-id <arn> --policy-name default --policy file://anything.json   # → AccessDenied
aws kms decrypt --key-id <arn> --ciphertext-blob fileb://some.bin --encryption-context app=condition-lock,...   # from the parent → AccessDenied
```

**What this does and doesn't guarantee**
- **The image is frozen.** The policy can never change, so only that exact image (PCR0) can
  decrypt with this key. To ship a new verifier, create a **new key** for the new PCR0 and seal
  new locks with it. Old locks stay with the old key and the old `.eif`, so keep both. A
  re-wrap path would have to run inside the old enclave, and it doesn't exist yet.
- **Key deletion:** `ScheduleKeyDeletion` is left to the auditor so the key can be retired
  (deletion has a 7 to 30 day waiting period). Deleting it destroys the escrow route for every
  lock under it; the tlock fail-safe still opens each vault on its date.
- **Residual trust:** AWS itself, the Nitro hypervisor, and AWS Support's account-recovery
  processes are outside this design. For keys that become unmanageable, AWS documents that you
  contact AWS Support.

## 5. Run it

On the parent:

```sh
# KMS reachability for the enclave (vsock 8000 → kms.<region>.amazonaws.com:443)
vsock-proxy 8000 kms.us-east-1.amazonaws.com 443 &        # or: systemctl enable --now nitro-enclaves-vsock-proxy

nitro-cli run-enclave --eif-path condlock-verifier-v1.eif --cpu-count 2 --memory 2048 --enclave-cid 16
nitro-cli describe-enclaves          # State RUNNING, Flags NONE (not DEBUG_MODE)

# Bridge the API's Unix socket to the enclave's vsock port 5005
sudo mkdir -p /run/condlock && sudo chown ec2-user /run/condlock
socat UNIX-LISTEN:/run/condlock/verifier.sock,fork VSOCK-CONNECT:16:5005 &
```

Run the API with `KMS_PROVIDER=aws`, `KMS_KEY_ID=<arn>`,
`VERIFIER_SOCKET=/run/condlock/verifier.sock`, `DATABASE_URL=...` and `ESCROW_ADMIN_TOKEN=...`.
The API encrypts with the instance role, and only the enclave can decrypt.

## Credentials (not implemented yet)

The enclave has no network and no instance metadata service, so it can't fetch the role's
credentials itself. The usual approach is for the parent to read short-lived credentials from
IMDS and hand them to the enclave over vsock, refreshing them before they expire. The parent
already holds those credentials, and the key policy still requires attestation, so passing
them grants nothing new. This plumbing is a follow-up. Until it exists, the enclave can't
reach KMS, and the code only runs end to end against the mocks.

## Checks to run once it's up

1. Lock a test vault through the API with a short time-lock. `POST /locks/:id/unlock` returns
   423 until drand reaches the round, then 200.
2. From the parent, `aws kms decrypt` on that lock's stored ciphertext returns AccessDenied.
3. `nitro-cli run-enclave ... --debug-mode` with the same image: unlock fails with
   `access-denied` in the audit log.
4. Change one byte of the verifier, rebuild, and run the new image: the PCR0 differs and unlock
   fails with `access-denied`.
5. Edit a lock row's condition in Postgres (drop the trigger first, as an admin could): unlock
   fails with `unwrap-failed`, because the seal is in the encryption context.

## Teardown

Terminate the instance. Schedule the KMS key for deletion as the auditor role
(`aws kms schedule-key-deletion --key-id <arn> --pending-window-in-days 7`) if you no longer
need it; see the deletion note in step 4 first. Check the KMS and EC2 pricing pages for what
you were billed.
