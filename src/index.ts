// --- Core API Functions ---
export { sign } from "./auth/sign.js";
export { verify } from "./auth/verify.js";

// --- Helper Functions ---
export { parseAuthToken } from "./auth/parseAuthToken.js";
export { generateNonce } from "./utils/nonce.js";

// --- Utility Exports ---
export { stringToUint8Array, uint8ArrayToString } from "./utils/encoding.js";

// --- Core Types ---
export type {
  NearAuthData,
  SignOptions,
  VerificationResult,
  VerifyOptions,
  WalletInterface,
} from "./types.js";
