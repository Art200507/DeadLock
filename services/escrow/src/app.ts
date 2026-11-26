/**
 * HTTP API (Hono). Every /locks route needs an Ed25519-signed request from a registered device.
 *
 *   POST /devices               register a device public key (admin token; setup only)
 *   POST /locks                 seal a lock: vault ID, condition, fail-safe, raw DEK (wrapped, never stored raw)
 *   GET  /locks/:id             status, condition and the latest verifier result
 *   POST /locks/:id/unlock      the DEK, once, if met or past the fail-safe; else 423 "still locked"
 *   GET  /locks/:id/log         the audit log
 *
 * No route edits or deletes a lock or its condition.
 */
import { createHash, timingSafeEqual } from "node:crypto";
import { Hono, type Context } from "hono";
import { Escrow, EscrowError, isVaultId } from "./escrow.js";
import { SIG_HEADERS, publicKeyFromRaw, verifySignature } from "./signing.js";

export const MAX_BODY_BYTES = 16 * 1024;
export const MAX_CLOCK_SKEW_MS = 5 * 60_000;

type Env = { Variables: { deviceId: string; body: string } };

export interface AppOptions {
  escrow: Escrow;
  /** Bearer token for POST /devices. If unset, device registration over HTTP is disabled. */
  adminToken?: string;
}

const sha256 = (s: string) => createHash("sha256").update(s).digest();

function safeEqual(a: string, b: string): boolean {
  return timingSafeEqual(sha256(a), sha256(b));
}

function fail(c: Context, status: EscrowError["status"], code: string, message: string, extra: Record<string, unknown> = {}) {
  return c.json({ error: code, message, ...extra }, status);
}

function parseJson(body: string): Record<string, unknown> {
  try {
    const v = JSON.parse(body) as unknown;
    if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error();
    return v as Record<string, unknown>;
  } catch {
    throw new EscrowError(400, "bad-json", "request body must be a JSON object");
  }
}

export function createApp({ escrow, adminToken }: AppOptions) {
  const app = new Hono<Env>();

  // Read the body once, with a size cap, so the signature covers exactly these bytes.
  app.use("*", async (c, next) => {
    const declared = Number(c.req.header("content-length") ?? "0");
    if (declared > MAX_BODY_BYTES) return fail(c, 400, "too-large", "request body too large");
    const body = c.req.method === "GET" || c.req.method === "HEAD" ? "" : await c.req.text();
    if (Buffer.byteLength(body) > MAX_BODY_BYTES) return fail(c, 400, "too-large", "request body too large");
    c.set("body", body);
    await next();
  });

  // Device signature check for /locks and everything under it.
  app.use("*", async (c, next) => {
    if (c.req.path !== "/locks" && !c.req.path.startsWith("/locks/")) return next();
    const url = new URL(c.req.url);
    const vaultId = c.req.path.split("/")[2];
    const auditVault = vaultId && isVaultId(vaultId) ? vaultId : null;
    const deny = async (reason: string, deviceId?: string) => {
      await escrow.audit(auditVault, "auth-failed", { reason, deviceId: deviceId ?? null, method: c.req.method, path: url.pathname });
      return fail(c, 401, "unauthorized", "request signature rejected");
    };

    const deviceId = c.req.header(SIG_HEADERS.device);
    const timestamp = c.req.header(SIG_HEADERS.timestamp);
    const nonce = c.req.header(SIG_HEADERS.nonce);
    const signature = c.req.header(SIG_HEADERS.signature);
    if (!deviceId || !timestamp || !nonce || !signature) return deny("missing-signature-headers", deviceId);
    if (!/^\d{1,16}$/.test(timestamp) || !/^[0-9a-f]{32}$/.test(nonce)) return deny("malformed-headers", deviceId);

    // Freshness is judged by the server's clock; the client's clock only has to be roughly right.
    const ts = Number(timestamp);
    const now = escrow.now().getTime();
    if (Math.abs(now - ts) > MAX_CLOCK_SKEW_MS) return deny("stale-or-future-timestamp", deviceId);

    const pub = await escrow.devicePublicKey(deviceId);
    if (!pub) return deny("unknown-device", deviceId);
    const ok = verifySignature(
      publicKeyFromRaw(pub),
      { method: c.req.method, path: url.pathname + url.search, timestamp, nonce, body: c.get("body") },
      signature,
    );
    if (!ok) return deny("bad-signature", deviceId);
    if (!(await escrow.useNonce(deviceId, nonce, new Date(Math.max(ts, now) + 2 * MAX_CLOCK_SKEW_MS)))) {
      return deny("replayed-nonce", deviceId);
    }
    c.set("deviceId", deviceId);
    await next();
  });

  app.post("/devices", async (c) => {
    if (!adminToken) return fail(c, 404, "not-found", "device registration is disabled");
    const auth = c.req.header("authorization") ?? "";
    if (!auth.startsWith("Bearer ") || !safeEqual(auth.slice(7), adminToken)) {
      await escrow.audit(null, "auth-failed", { reason: "bad-admin-token", path: "/devices" });
      return fail(c, 401, "unauthorized", "admin token required");
    }
    const body = parseJson(c.get("body"));
    if (typeof body.publicKey !== "string") throw new EscrowError(400, "bad-request", "publicKey is required");
    try {
      publicKeyFromRaw(body.publicKey);
    } catch {
      throw new EscrowError(400, "bad-request", "publicKey must be a raw Ed25519 key, base64url");
    }
    const label = typeof body.label === "string" ? body.label : "";
    return c.json(await escrow.registerDevice(body.publicKey, label), 201);
  });

  app.post("/locks", async (c) => {
    const body = parseJson(c.get("body"));
    const lock = await escrow.createLock({
      vaultId: body.vaultId,
      condition: body.condition,
      failsafeAt: body.failsafeAt,
      dek: body.dek,
      deviceId: c.get("deviceId"),
    });
    return c.json(lock, 201);
  });

  app.get("/locks/:id", async (c) => c.json(await escrow.getLock(c.req.param("id"))));

  app.post("/locks/:id/unlock", async (c) => {
    const { dek, via } = await escrow.unlock(c.req.param("id"), c.get("deviceId"));
    try {
      return c.json({ vaultId: c.req.param("id"), via, dek: Buffer.from(dek).toString("base64") });
    } finally {
      dek.fill(0);
    }
  });

  app.get("/locks/:id/log", async (c) => c.json({ vaultId: c.req.param("id"), entries: await escrow.log(c.req.param("id")) }));

  app.notFound((c) => fail(c, 404, "not-found", "no such route"));

  app.onError((err, c) => {
    if (err instanceof EscrowError) return fail(c, err.status, err.code, err.message, err.extra);
    console.error("escrow: unhandled error:", err instanceof Error ? err.name : "unknown");
    return fail(c, 500, "internal", "internal error");
  });

  return app;
}
