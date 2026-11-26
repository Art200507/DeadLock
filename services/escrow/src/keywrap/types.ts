/**
 * The key-wrapping seam. Everything that protects a vault's data key at rest in the escrow
 * goes through `KeyWrapper`: today AWS KMS (and a local mock for tests); later, other layers
 * such as a post-quantum hybrid wrap or a threshold / split-key scheme can plug in as further
 * implementations without touching the API, the database schema or stored locks.
 *
 * Contract:
 *  - `wrap` binds the ciphertext to `context`: the vault ID and the seal hash (the sealed
 *    condition and fail-safe). `unwrap` with any other context must fail, so a stored key can't
 *    be moved to another vault or released under an edited condition. For KMS this is the
 *    EncryptionContext; for other layers it's associated data.
 *  - `WrappedKey` is self-describing (`scheme`, `keyId`) and stored as-is (JSONB), so old locks
 *    keep unwrapping after the default wrapper changes.
 *  - Wrappers never log or persist the plaintext key.
 */

export interface WrapContext {
  /** Hex vault ID the key belongs to. */
  vaultId: string;
  /** sha256 hex of the sealed terms (vault ID, condition, fail-safe); see conditions.sealHash. */
  seal: string;
}

export interface WrappedKey {
  /** Which wrapper made this, versioned, e.g. "aws-kms/v1". */
  scheme: string;
  /** Which key/key-set inside that scheme (KMS key ARN, mock key ID, ...). */
  keyId: string;
  /** Scheme-specific ciphertext, base64. A composite scheme may put JSON here. */
  ciphertext: string;
  /** Optional scheme-specific parameters (for future layers). Never secret. */
  params?: Record<string, unknown>;
}

/** Per-lock inputs for layers that need them; single-key wrappers ignore these. */
export interface WrapOptions {
  /** A trusted person's age public key ("age1..."), for the 2-of-3 split's third share. */
  guardianRecipient?: string;
}

export interface UnwrapOptions {
  /** The guardian's decrypted share, supplied at unlock time when another holder is unavailable. */
  guardianShare?: Uint8Array;
}

export interface KeyWrapper {
  readonly scheme: string;
  wrap(plaintext: Uint8Array, context: WrapContext, options?: WrapOptions): Promise<WrappedKey>;
  unwrap(wrapped: WrappedKey, context: WrapContext, options?: UnwrapOptions): Promise<Uint8Array>;
}

/** The ciphertext doesn't open under this context or key (tampered, moved or wrong key). */
export class UnwrapError extends Error {
  override name = "UnwrapError";
}

/** The key policy refused this caller (e.g. no valid enclave attestation for the required PCR0). */
export class KeyAccessDeniedError extends UnwrapError {
  override name = "KeyAccessDeniedError";
}

/** A wrapper input was invalid (e.g. a malformed guardian public key). Maps to 400. */
export class WrapInputError extends Error {
  override name = "WrapInputError";
}

/** The key service itself failed (network, permissions, throttling). Retry may help. */
export class KeyServiceError extends Error {
  override name = "KeyServiceError";
}

/** The context every wrapper binds to, in a stable form. */
export function contextFields(context: WrapContext): Record<string, string> {
  if (!/^[0-9a-f]{32}$/.test(context.vaultId)) throw new TypeError("vaultId must be 32 lowercase hex chars");
  if (!/^[0-9a-f]{64}$/.test(context.seal)) throw new TypeError("seal must be 64 lowercase hex chars");
  return { app: "condition-lock", vaultId: context.vaultId, seal: context.seal };
}

export function canonicalContext(context: WrapContext): string {
  const f = contextFields(context);
  return JSON.stringify(Object.fromEntries(Object.keys(f).sort().map((k) => [k, f[k]])));
}

/**
 * Picks the wrapper for new locks (`primary`) and finds the right one, by scheme, to unwrap
 * any stored key. Add a new layer by registering its wrapper; switch the default by making
 * it primary. Old locks keep working as long as their wrapper stays registered.
 */
export class KeyWrapRegistry {
  private readonly byScheme = new Map<string, KeyWrapper>();

  constructor(
    readonly primary: KeyWrapper,
    others: KeyWrapper[] = [],
  ) {
    for (const w of [primary, ...others]) {
      if (this.byScheme.has(w.scheme)) throw new Error(`duplicate key wrapper scheme ${w.scheme}`);
      this.byScheme.set(w.scheme, w);
    }
  }

  async wrap(plaintext: Uint8Array, context: WrapContext, options?: WrapOptions): Promise<WrappedKey> {
    return this.primary.wrap(plaintext, context, options);
  }

  async unwrap(wrapped: WrappedKey, context: WrapContext, options?: UnwrapOptions): Promise<Uint8Array> {
    const w = this.byScheme.get(wrapped.scheme);
    if (!w) throw new UnwrapError(`no key wrapper registered for scheme ${wrapped.scheme}`);
    return w.unwrap(wrapped, context, options);
  }

  get schemes(): string[] {
    return [...this.byScheme.keys()];
  }
}

export function isWrappedKey(x: unknown): x is WrappedKey {
  const o = x as WrappedKey;
  return (
    typeof o === "object" &&
    o !== null &&
    typeof o.scheme === "string" &&
    typeof o.keyId === "string" &&
    typeof o.ciphertext === "string"
  );
}
