/**
 * near-sign-verify
 * NEAR wallet signature generation utility for API authentication
 */

// Export auth functions
export { createAuthToken } from "./auth/createAuthToken.js";
export { verify, VerifyOptions } from "./auth/verify.js";
export { parseAuthToken } from "./auth/parseAuthToken.js";

// Export utility functions
export { generateNonce, validateNonce } from "./utils/nonce.js";
export {
  stringToUint8Array,
  uint8ArrayToString,
  base64ToUint8Array,
  uint8ArrayToBase64,
} from "./utils/encoding.js";

// Export crypto constants
export { TAG, ED25519_PREFIX } from "./crypto/crypto.js";

// Export types
export type {
  NearAuthData,
  NearAuthPayload,
  ValidationResult,
} from "./types.js";

// Export schemas
export {
  NearAuthDataSchema,
  NearAuthPayloadSchema,
  ValidationResultSchema,
} from "./types.js";
