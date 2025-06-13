// --- Core API Functions ---
export { sign } from "./auth/sign.js";
export { verify } from "./auth/verify.js";

// --- Helper Functions ---
export { parseAuthToken } from "./auth/parseAuthToken.js";
export { generateNonce, validateNonce } from "./utils/nonce.js";

// --- Utility Exports ---
export { ED25519_PREFIX, TAG } from "./crypto/crypto.js";
export {
  base64ToUint8Array,
  stringToUint8Array,
  uint8ArrayToBase64,
  uint8ArrayToString,
} from "./utils/encoding.js";

// --- Core Types ---
export type {
  // NEP-413 Aligned Types
  SignMessageParams,
  SignedMessage,
  SignedPayload,
  // Library's main API types
  SignOptions,
  VerificationResult,
  VerifyOptions,
  WalletInterface,
} from "./types.js";
