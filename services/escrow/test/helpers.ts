import { randomBytes } from "node:crypto";
import * as fsp from "node:fs/promises";
import type { Server } from "node:net";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { MockDrand } from "../../../packages/core/test/helpers/mock-drand.js";
import { createApp } from "../src/app.js";
import { migrate, pgliteClient, type SqlClient } from "../src/db.js";
import { DAY_MS, Escrow } from "../src/escrow.js";
import { MockKms, MockKmsService, MockNsm } from "../src/keywrap/mock-kms.js";
import { KeyWrapRegistry, type KeyWrapper } from "../src/keywrap/types.js";
import { generateDeviceKeyPair, signRequest, type DeviceKeyPair } from "../src/signing.js";
import type { KeyReleaser } from "../src/verifier/protocol.js";
import { InProcessReleaser, SocketReleaser, serveVerifier } from "../src/verifier/transport.js";
import { KeyReleaseVerifier } from "../src/verifier/verifier.js";
import type { SecretStore } from "../src/verifier/secrets.js";
import type { NflChecker } from "../src/verifiers/nfl.js";

/** Not a secret: only ever used against an in-memory test database. */
export const TEST_ADMIN_TOKEN = "test-admin-token-not-a-secret";
/** The "enclave image measurement" our mock key policy requires. */
export const ENCLAVE_PCR0 = "ab".repeat(48);

export const vaultId = () => randomBytes(16).toString("hex");
export const newDek = () => new Uint8Array(randomBytes(32));
export const b64 = (u: Uint8Array) => Buffer.from(u).toString("base64");
export { DAY_MS, MockDrand };

export interface Device extends DeviceKeyPair {
  deviceId: string;
}

export interface HarnessOptions {
  /** Wrap-side KMS (API). Default: a MockKms on a shared mock key service. */
  kms?: KeyWrapper;
  /** Verifier-side KMS. Default: same mock key service (or the attested one in enclave mode). */
  verifierKms?: KeyWrapper;
  /** Mock the Nitro setup: key policy requires attestation for ENCLAVE_PCR0; verifier attests. */
  enclave?: boolean | { verifierPcr0: string };
  /** Run the verifier behind a real Unix socket instead of in-process. */
  socket?: boolean;
  releaser?: KeyReleaser;
  /** Full control over both sides' key registries (2-of-3 tests). Overrides kms/verifierKms. */
  apiKeys?: KeyWrapRegistry;
  verifierKeys?: KeyWrapRegistry;
  nfl?: NflChecker;
  secrets?: SecretStore;
}

export interface Harness {
  db: SqlClient;
  escrow: Escrow;
  kms: KeyWrapper;
  service: MockKmsService | undefined;
  drand: MockDrand;
  verifier: KeyReleaseVerifier;
  /** The verifier's Unix socket, when socket: true. */
  socketPath: string | undefined;
  app: ReturnType<typeof createApp>;
  /** The server clock; use setTime to move it (drand follows). */
  clock: { now: Date };
  setTime(d: Date | number): void;
  device: Device;
  registerDevice(label?: string): Promise<Device>;
  call(
    method: string,
    path: string,
    body?: unknown,
    opts?: { device?: Device; timestamp?: number; nonce?: string; tamper?: (h: Record<string, string>) => void; rawBody?: string },
  ): Promise<{ status: number; json: Record<string, any> }>;
  close(): Promise<void>;
}

export async function harness(opts: HarnessOptions = {}): Promise<Harness> {
  const db = await pgliteClient();
  await migrate(db);
  const clock = { now: new Date("2026-12-01T12:00:00.000Z") };
  const drand = new MockDrand();
  const latestRoundAt = (t: number) => Math.floor((t - drand.info.genesis_time * 1000) / (drand.info.period * 1000)) + 1;
  const setTime = (d: Date | number) => {
    clock.now = new Date(d);
    drand.publish(latestRoundAt(clock.now.getTime()));
  };
  setTime(clock.now);

  let service: MockKmsService | undefined;
  let kms = opts.kms;
  let verifierKms = opts.verifierKms;
  if (!kms) {
    if (opts.enclave) {
      const root = MockNsm.newRoot();
      service = new MockKmsService({ policy: { requireAttestedPcr0: ENCLAVE_PCR0 }, attestationRoot: root.publicKey });
      const pcr0 = typeof opts.enclave === "object" ? opts.enclave.verifierPcr0 : ENCLAVE_PCR0;
      verifierKms ??= new MockKms({ service, attestation: new MockNsm(pcr0, root.privateKey) });
    } else {
      service = new MockKmsService();
    }
    kms = new MockKms({ service });
  }
  verifierKms ??= kms;

  const verifier = new KeyReleaseVerifier({
    keys: opts.verifierKeys ?? new KeyWrapRegistry(verifierKms),
    chain: drand.chainParams,
    ...(opts.nfl ? { nfl: opts.nfl } : {}),
    ...(opts.secrets ? { secrets: opts.secrets } : {}),
  });
  let server: Server | undefined;
  let socketDir: string | undefined;
  let socketPath: string | undefined;
  let releaser = opts.releaser;
  if (!releaser && opts.socket) {
    socketDir = await fsp.mkdtemp(path.join(tmpdir(), "condlock-verifier-"));
    socketPath = path.join(socketDir, "verifier.sock");
    server = await serveVerifier(verifier, { path: socketPath });
    releaser = new SocketReleaser({ path: socketPath });
  }
  releaser ??= new InProcessReleaser(verifier);

  const escrow = new Escrow({ db, keys: opts.apiKeys ?? new KeyWrapRegistry(kms), releaser, drand, now: () => new Date(clock.now) });
  const app = createApp({ escrow, adminToken: TEST_ADMIN_TOKEN });

  const registerDevice = async (label = "test laptop"): Promise<Device> => {
    const kp = generateDeviceKeyPair();
    const res = await app.request("/devices", {
      method: "POST",
      headers: { authorization: `Bearer ${TEST_ADMIN_TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify({ publicKey: kp.publicKey, label }),
    });
    if (res.status !== 201) throw new Error(`device registration failed: ${res.status} ${await res.text()}`);
    const { deviceId } = (await res.json()) as { deviceId: string };
    return { ...kp, deviceId };
  };

  const device = await registerDevice();

  const call: Harness["call"] = async (method, p, body, o = {}) => {
    const d = o.device ?? device;
    const raw = o.rawBody ?? (body === undefined ? "" : JSON.stringify(body));
    const headers: Record<string, string> = {
      ...signRequest({
        deviceId: d.deviceId,
        privateKey: d.privateKey,
        method,
        path: p,
        body: raw,
        timestamp: o.timestamp ?? clock.now.getTime(),
        ...(o.nonce ? { nonce: o.nonce } : {}),
      }),
      "content-type": "application/json",
    };
    o.tamper?.(headers);
    const res = await app.request(p, { method, headers, ...(method === "GET" ? {} : { body: raw }) });
    const text = await res.text();
    return { status: res.status, json: text ? (JSON.parse(text) as Record<string, any>) : {} };
  };

  const close = async () => {
    await db.close();
    if (server) await new Promise<void>((r) => server!.close(() => r()));
    if (socketDir) await fsp.rm(socketDir, { recursive: true, force: true });
  };

  return { db, escrow, kms, service, drand, verifier, socketPath, app, clock, setTime, device, registerDevice, call, close };
}

/** A valid time-lock body: unlocks in 1 hour, fail-safe in 1 year (server clock). */
export function timeLockBody(h: Harness, overrides: Record<string, unknown> = {}) {
  const now = h.clock.now.getTime();
  return {
    vaultId: vaultId(),
    condition: { type: "time", unlockAt: new Date(now + 3_600_000).toISOString() },
    failsafeAt: new Date(now + 365 * DAY_MS).toISOString(),
    dek: b64(newDek()),
    ...overrides,
  };
}
