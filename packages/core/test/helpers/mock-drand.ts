/**
 * An offline drand network for tests. It has its own throwaway BLS key, publishes rounds
 * only when the test says so, and signs beacons exactly like quicknet does
 * (bls-unchained-g1-rfc9380: G1 signature over sha256(round as u64 big-endian)),
 * so drand-client's real beacon verification and tlock-js's real IBE decryption run against it.
 */
import { bls12_381 as bls } from "@noble/curves/bls12-381";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "node:crypto";
import type { ChainClient, ChainInfo, ChainOptions, RandomnessBeacon } from "drand-client";
import { chainFromInfo, type DrandChain } from "../../src/index.js";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

export class MockDrand implements ChainClient {
  options: ChainOptions = { disableBeaconVerification: false, noCache: false };
  readonly info: ChainInfo;
  readonly chainParams: DrandChain;
  /** Highest round "published" so far. */
  latestRound = 0;
  /** Simulate drand being unreachable. */
  offline = false;
  /** Serve a beacon for a different round than requested (a lying relay). */
  serveWrongRound = false;
  calls = { get: 0, latest: 0, info: 0 };
  private readonly sk: Uint8Array;

  constructor(genesisTime = 1_700_000_000, period = 3) {
    this.sk = bls.utils.randomPrivateKey();
    this.info = {
      public_key: hex(bls.getPublicKeyForShortSignatures(this.sk)),
      period,
      genesis_time: genesisTime,
      hash: hex(randomBytes(32)),
      groupHash: hex(randomBytes(32)),
      schemeID: "bls-unchained-g1-rfc9380",
      metadata: { beaconID: "mock-quicknet" },
    };
    this.chainParams = chainFromInfo(this.info);
  }

  publish(round: number) {
    this.latestRound = Math.max(this.latestRound, round);
  }

  beacon(round: number): RandomnessBeacon {
    const msg = sha256(u64be(round));
    const sig = bls.signShortSignature(msg, this.sk) as Uint8Array;
    return { round, signature: hex(sig), randomness: hex(sha256(sig)) };
  }

  private net() {
    if (this.offline) throw new TypeError("fetch failed");
  }

  async get(round: number): Promise<RandomnessBeacon> {
    this.calls.get++;
    this.net();
    if (round > this.latestRound) throw new Error(`Error response fetching mock://public/${round} - got 425`);
    return this.beacon(this.serveWrongRound ? round + 1 : round);
  }

  async latest(): Promise<RandomnessBeacon> {
    this.calls.latest++;
    this.net();
    return this.beacon(this.latestRound);
  }

  chain() {
    return {
      baseUrl: "mock://drand",
      info: async () => {
        this.calls.info++;
        this.net();
        return this.info;
      },
    };
  }
}

function u64be(n: number): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), false);
  return b;
}
