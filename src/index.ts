/**
 * near-simple-signing
 * NEAR wallet signature generation utility for API authentication
 */

// Export auth functions
export { createAuthHeader } from './auth/createAuthHeader.js';
export { validateSignature } from './auth/validateSignature.js';

// Export utility functions
export { generateNonce, validateNonce } from './utils/nonce.js';
export {
  stringToUint8Array,
  uint8ArrayToString,
  base64ToUint8Array,
  uint8ArrayToBase64,
} from './utils/encoding.js';

// Export crypto constants
export { TAG, ED25519_PREFIX } from './crypto/crypto.js';

// Export types
export type {
  NearAuthData,
  NearAuthPayload,
  ValidationResult,
  ValidateSignatureParams,
} from './types.js';
