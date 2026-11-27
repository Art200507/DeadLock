#!/usr/bin/env node
// Test-only stand-in for the enclave's nsm-attest helper: reads the ephemeral public key (SPKI
// DER) on stdin and prints a mock attestation document for MOCK_NSM_PCR0, signed by the mock
// Nitro root key in MOCK_NSM_ROOT_KEY (a throwaway PEM in the test's temp directory). Same
// format as MockNsm in services/escrow/src/keywrap/mock-kms.ts.
import { createPrivateKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";

const chunks = [];
for await (const c of process.stdin) chunks.push(c);
const doc = {
  format: "mock-nitro-attestation/v1",
  moduleId: "mock-enclave-e2e",
  pcrs: { 0: process.env.MOCK_NSM_PCR0 },
  publicKey: Buffer.concat(chunks).toString("base64"),
  timestamp: Date.now(),
};
const key = createPrivateKey(readFileSync(process.env.MOCK_NSM_ROOT_KEY, "utf8"));
const signature = sign(null, Buffer.from(JSON.stringify(doc)), key).toString("base64");
process.stdout.write(JSON.stringify({ doc, signature }));
