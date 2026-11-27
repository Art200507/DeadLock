/** Device request signing lives in @condlock/core so the CLI and the server share one implementation. */
export {
  SIG_HEADERS,
  canonicalRequest,
  generateDeviceKeyPair,
  publicKeyFromRaw,
  signRequest,
  verifySignature,
  type CanonicalRequest,
  type DeviceKeyPair,
  type SignOptions,
} from "@condlock/core";
