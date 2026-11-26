/**
 * drand timelock (tlock) wrapping of a vault's 256-bit data key.
 *
 * The DEK is encrypted with tlock-js to a future round of drand's quicknet. It can only be
 * decrypted with that round's BLS signature, which the League of Entropy publishes when the
 * round arrives and not before. Nobody holds a key that opens it early: not us, not the
 * escrow server, not the owner.
 *
 * Unlock is decided only by drand: if the round's beacon can be fetched and verifies, the
 * key opens; if drand's latest published round is earlier, the vault is still locked. The
 * laptop clock is never consulted. (tlock-js's own `timelockDecrypt` refuses based on
 * `Date.now()`, so unwrapping uses tlock-js's age and IBE modules with our own stanza
 * handler instead. All cryptography is tlock-js / drand-client / noble; none is custom.)
 *
 * Payload sealed inside the timelock: "CLT1" | vaultId (16 B) | DEK (32 B).
 */
import { Buffer } from "node:buffer";
import { fetchBeacon, type ChainClient, type ChainInfo, type RandomnessBeacon } from "drand-client";
import { HttpCachingChain, HttpChainClient, timelockEncrypt } from "tlock-js";
import { decryptAge, type Stanza } from "tlock-js/age/age-encrypt-decrypt.js";
import { decodeArmor, isProbablyArmored } from "tlock-js/age/armor.js";
import { decryptOnG2 } from "tlock-js/crypto/ibe.js";
import { bytesEqual, concatBytes, fromHex, toHex } from "./bytes.js";
import { DEK_LENGTH, ID_LENGTH } from "./keys.js";
import { IntegrityError } from "./stream.js";

/** The drand chain parameters we pin and store next to every wrapped key. */
export interface DrandChain {
  /** Chain hash (identifies the network). */
  hash: string;
  /** Group public key on G2, hex. */
  publicKey: string;
  /** Seconds between rounds. */
  period: number;
  /** Unix seconds of round 1. */
  genesisTime: number;
  schemeID: string;
  beaconID: string;
  groupHash: string;
}

/** drand quicknet (League of Entropy mainnet, 3-second rounds, unchained, RFC 9380). */
export const QUICKNET: Readonly<DrandChain> = Object.freeze({
  hash: "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
  publicKey:
    "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a",
  period: 3,
  genesisTime: 1692803367,
  schemeID: "bls-unchained-g1-rfc9380",
  beaconID: "quicknet",
  groupHash: "f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e",
});

/** Public drand HTTP relays that serve quicknet. */
export const QUICKNET_RELAYS = [
  "https://api.drand.sh",
  "https://api2.drand.sh",
  "https://api3.drand.sh",
  "https://drand.cloudflare.com",
] as const;

/** Everything needed to unwrap later, stored alongside the vault. Safe to back up anywhere. */
export interface TlockEnvelope {
  format: "condlock-tlock";
  version: 1;
  vaultId: string;
  /** The drand round whose signature opens the key. */
  round: number;
  /** When that round is published, derived from the chain parameters (UTC, ISO 8601). */
  unlockAt: string;
  chain: DrandChain;
  /** tlock-js age ciphertext, ASCII armored. */
  ciphertext: string;
}

/** The round has not been published by drand yet. */
export class StillLockedError extends Error {
  override name = "StillLockedError";
  constructor(
    readonly round: number,
    readonly unlockAt: Date,
    readonly latestRound: number,
  ) {
    super(`still locked until ${unlockAt.toISOString()} (drand round ${round}; latest published is ${latestRound})`);
  }
}

/** drand could not be reached or returned something unverifiable, so lock state is unknown. */
export class DrandUnavailableError extends Error {
  override name = "DrandUnavailableError";
}

const PAYLOAD_MAGIC = new Uint8Array([0x43, 0x4c, 0x54, 0x31]); // "CLT1"
const G2_POINT_LENGTH = 96; // compressed BLS12-381 G2 point (the IBE "U" for quicknet)
const SUPPORTED_SCHEME = "bls-unchained-g1-rfc9380";

// ---------- rounds and time ----------

function toMillis(t: Date | number | string): number {
  const ms = t instanceof Date ? t.getTime() : typeof t === "number" ? t : Date.parse(t);
  if (!Number.isFinite(ms)) throw new RangeError(`invalid time: ${String(t)}`);
  return ms;
}

/** When `round` is published: genesis + (round - 1) * period. */
export function timeOfRound(round: number, chain: DrandChain = QUICKNET): Date {
  if (!Number.isSafeInteger(round) || round < 1) throw new RangeError(`invalid round: ${round}`);
  return new Date((chain.genesisTime + (round - 1) * chain.period) * 1000);
}

/**
 * The earliest drand round published at or after `time` (UTC), so a lock never opens early.
 * Pure arithmetic on the chain parameters; it does not read any clock.
 */
export function roundForTime(time: Date | number | string, chain: DrandChain = QUICKNET): number {
  const ms = toMillis(time);
  const genesisMs = chain.genesisTime * 1000;
  if (ms < genesisMs) throw new RangeError("time is before the drand chain's genesis");
  const periodMs = chain.period * 1000;
  return Math.ceil((ms - genesisMs) / periodMs) + 1;
}

// ---------- drand clients ----------

function toChainInfo(chain: DrandChain): ChainInfo {
  return {
    hash: chain.hash,
    public_key: chain.publicKey,
    period: chain.period,
    genesis_time: chain.genesisTime,
    schemeID: chain.schemeID,
    groupHash: chain.groupHash,
    metadata: { beaconID: chain.beaconID },
  };
}

export function chainFromInfo(info: ChainInfo): DrandChain {
  return {
    hash: info.hash,
    publicKey: info.public_key,
    period: info.period,
    genesisTime: info.genesis_time,
    schemeID: info.schemeID,
    beaconID: info.metadata?.beaconID ?? "",
    groupHash: info.groupHash,
  };
}

/** An HTTP drand client pinned to `chain`: chain info must match and every beacon is BLS-verified. */
export function createDrandClient(
  chain: DrandChain = QUICKNET,
  relay: string = QUICKNET_RELAYS[0],
): ChainClient {
  const options = {
    disableBeaconVerification: false,
    noCache: false,
    chainVerificationParams: { chainHash: chain.hash, publicKey: chain.publicKey },
  };
  const url = `${relay.replace(/\/+$/, "")}/${chain.hash}`;
  return new HttpChainClient(new HttpCachingChain(url, options), options, { userAgent: "condlock" });
}

/** A client that knows only the pinned chain info: lets wrapping run with no network at all. */
function offlineClient(chain: DrandChain): ChainClient {
  const info = toChainInfo(chain);
  const noNetwork = async (): Promise<never> => {
    throw new Error("offline client: wrapping never fetches beacons");
  };
  return {
    options: { disableBeaconVerification: false, noCache: false },
    chain: () => ({ baseUrl: "offline:", info: async () => info }),
    get: noNetwork,
    latest: noNetwork,
  };
}

// ---------- wrap / unwrap ----------

export type WrapTarget = { unlockAt: Date | number | string } | { round: number };

export interface WrapOptions {
  dek: Uint8Array;
  /** Hex vault ID; sealed inside the timelock so an envelope can't be moved to another vault. */
  vaultId: string;
  /** Either a UTC time (rounded up to the next drand round) or an exact round. */
  target: WrapTarget;
  chain?: DrandChain;
}

/** Timelock-encrypt the DEK. Runs offline: only the pinned chain public key is needed. */
export async function wrapDek(opts: WrapOptions): Promise<TlockEnvelope> {
  const chain = opts.chain ?? QUICKNET;
  if (chain.schemeID !== SUPPORTED_SCHEME) throw new Error(`unsupported drand scheme ${chain.schemeID}`);
  if (!(opts.dek instanceof Uint8Array) || opts.dek.length !== DEK_LENGTH) {
    throw new TypeError(`data key must be ${DEK_LENGTH} bytes`);
  }
  const vaultIdBytes = fromHex(opts.vaultId, ID_LENGTH);
  const round = "round" in opts.target ? opts.target.round : roundForTime(opts.target.unlockAt, chain);
  const unlockAt = timeOfRound(round, chain); // validates the round too

  const payload = concatBytes([PAYLOAD_MAGIC, vaultIdBytes, opts.dek]);
  try {
    const ciphertext = await timelockEncrypt(round, Buffer.from(payload), offlineClient(chain));
    return {
      format: "condlock-tlock",
      version: 1,
      vaultId: toHex(vaultIdBytes),
      round,
      unlockAt: unlockAt.toISOString(),
      chain: { ...chain },
      ciphertext,
    };
  } finally {
    payload.fill(0);
  }
}

export interface UnwrapOptions {
  /** drand client to ask; defaults to the pinned quicknet HTTP client. Must verify beacons. */
  client?: ChainClient;
}

/**
 * Recover the DEK once drand has published the envelope's round.
 * Throws StillLockedError before then, DrandUnavailableError if drand can't be asked, and
 * IntegrityError for a tampered or mismatched envelope.
 */
export async function unwrapDek(envelope: TlockEnvelope, opts: UnwrapOptions = {}): Promise<Uint8Array> {
  const env = parseTlockEnvelope(envelope);
  const client = opts.client ?? createDrandClient(env.chain);
  if (client.options.disableBeaconVerification) {
    throw new Error("refusing a drand client with beacon verification disabled");
  }

  let info: ChainInfo;
  try {
    info = await client.chain().info();
  } catch (err) {
    throw new DrandUnavailableError("could not fetch drand chain info", { cause: err });
  }
  if (info.hash !== env.chain.hash || info.public_key !== env.chain.publicKey || info.schemeID !== env.chain.schemeID) {
    throw new IntegrityError("drand client is for a different chain than the envelope");
  }

  const unlockAt = timeOfRound(env.round, env.chain);
  const unwrapFileKey = async (recipients: Stanza[]): Promise<Uint8Array> => {
    const stanzas = recipients.filter((s) => s.type === "tlock");
    if (stanzas.length !== 1 || recipients.length !== 1) throw new IntegrityError("expected exactly one tlock stanza");
    const { args, body } = stanzas[0]!;
    if (args.length !== 2 || args[0] !== String(env.round) || args[1] !== env.chain.hash) {
      throw new IntegrityError("timelock ciphertext is for a different round or chain than the envelope says");
    }
    const beacon = await fetchVerifiedBeacon(client, env.round, unlockAt);
    const rest = body.length - G2_POINT_LENGTH;
    if (rest <= 0 || rest % 2 !== 0) throw new IntegrityError("malformed tlock stanza");
    return decryptOnG2(Buffer.from(beacon.signature, "hex"), {
      U: body.subarray(0, G2_POINT_LENGTH),
      V: body.subarray(G2_POINT_LENGTH, G2_POINT_LENGTH + rest / 2),
      W: body.subarray(G2_POINT_LENGTH + rest / 2),
    });
  };

  let payload: Uint8Array;
  try {
    const cipher = isProbablyArmored(env.ciphertext) ? decodeArmor(env.ciphertext) : env.ciphertext;
    payload = new Uint8Array(await decryptAge(cipher, unwrapFileKey));
  } catch (err) {
    if (err instanceof StillLockedError || err instanceof DrandUnavailableError || err instanceof IntegrityError) {
      throw err;
    }
    throw new IntegrityError("timelock ciphertext failed to decrypt (tampered or wrong round)", { cause: err });
  }

  try {
    if (
      payload.length !== PAYLOAD_MAGIC.length + ID_LENGTH + DEK_LENGTH ||
      !bytesEqual(payload.subarray(0, PAYLOAD_MAGIC.length), PAYLOAD_MAGIC)
    ) {
      throw new IntegrityError("timelock payload is not a Condition Lock key");
    }
    const sealedVaultId = payload.subarray(PAYLOAD_MAGIC.length, PAYLOAD_MAGIC.length + ID_LENGTH);
    if (!bytesEqual(sealedVaultId, fromHex(env.vaultId, ID_LENGTH))) {
      throw new IntegrityError("timelock envelope belongs to a different vault");
    }
    return payload.slice(PAYLOAD_MAGIC.length + ID_LENGTH);
  } finally {
    payload.fill(0);
  }
}

/** Fetch and BLS-verify a round's beacon; if it isn't there, ask drand whether it's simply not out yet. */
async function fetchVerifiedBeacon(client: ChainClient, round: number, unlockAt: Date): Promise<RandomnessBeacon> {
  try {
    return await fetchBeacon(client, round);
  } catch (fetchErr) {
    let latest: RandomnessBeacon;
    try {
      latest = await client.latest();
    } catch {
      throw new DrandUnavailableError(`could not reach drand to check round ${round}`, { cause: fetchErr });
    }
    if (Number.isSafeInteger(latest?.round) && latest.round < round) {
      throw new StillLockedError(round, unlockAt, latest.round);
    }
    throw new DrandUnavailableError(
      `drand reports round ${latest?.round} but round ${round} could not be fetched or verified`,
      { cause: fetchErr },
    );
  }
}

// ---------- envelope (de)serialisation ----------

/** Validate an envelope read from disk (JSON text or a parsed object). */
export function parseTlockEnvelope(input: string | unknown): TlockEnvelope {
  let o: unknown = input;
  if (typeof input === "string") {
    try {
      o = JSON.parse(input);
    } catch {
      throw new IntegrityError("timelock envelope is not valid JSON");
    }
  }
  const bad = (why: string): never => {
    throw new IntegrityError(`invalid timelock envelope: ${why}`);
  };
  if (typeof o !== "object" || o === null) bad("not an object");
  const e = o as Record<string, unknown>;
  if (e.format !== "condlock-tlock" || e.version !== 1) bad("unknown format");
  if (typeof e.vaultId !== "string") bad("vaultId");
  try {
    fromHex(e.vaultId as string, ID_LENGTH);
  } catch {
    bad("vaultId");
  }
  if (typeof e.round !== "number" || !Number.isSafeInteger(e.round) || (e.round as number) < 1) bad("round");
  if (typeof e.ciphertext !== "string") bad("ciphertext");
  const c = e.chain as Record<string, unknown> | undefined;
  if (
    !c ||
    typeof c.hash !== "string" ||
    typeof c.publicKey !== "string" ||
    typeof c.period !== "number" ||
    !((c.period as number) > 0) ||
    typeof c.genesisTime !== "number" ||
    typeof c.schemeID !== "string" ||
    typeof c.beaconID !== "string" ||
    typeof c.groupHash !== "string"
  ) {
    bad("chain");
  }
  if (c!.schemeID !== SUPPORTED_SCHEME) bad(`unsupported scheme ${String(c!.schemeID)}`);
  const env = o as TlockEnvelope;
  if (env.unlockAt !== timeOfRound(env.round, env.chain).toISOString()) bad("unlockAt does not match round");
  return env;
}

export function serializeTlockEnvelope(env: TlockEnvelope): string {
  return JSON.stringify(env, null, 2) + "\n";
}
