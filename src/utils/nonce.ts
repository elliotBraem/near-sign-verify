import type { ValidationResult } from "../types.js";
import { uint8ArrayToBase64 } from "./encoding.js";

/**
 * Default max age for nonce validation (24 hours in milliseconds)
 */
const DEFAULT_MAX_AGE = 24 * 60 * 60 * 1000;

/**
 * Generate a timestamp-based nonce
 * @returns A 32-byte Uint8Array containing the padded timestamp
 */
export function generateNonce(): Uint8Array {
  const timestamp = Date.now().toString();
  const randomBytes = crypto.getRandomValues(new Uint8Array(16));
  const encoder = new TextEncoder();
  const nonceArray = new Uint8Array(32);

  // First 16 bytes: padded timestamp
  const timestampBytes = encoder.encode(timestamp.padStart(16, "0"));
  nonceArray.set(timestampBytes.slice(0, 16));

  // Last 16 bytes: random data for uniqueness
  nonceArray.set(randomBytes, 16);

  return nonceArray;
}

/**
 * Validate a nonce
 * @param nonce Nonce as Uint8Array
 * @param maxAge Maximum age of nonce in milliseconds (defaults to 24 hours)
 * @returns Validation result
 */
export function validateNonce(
  nonce: Uint8Array,
  maxAge: number = DEFAULT_MAX_AGE,
): ValidationResult {
  try {
    // Check nonce length
    if (nonce.length !== 32) {
      return { valid: false, error: "Invalid nonce length" };
    }

    // Extract timestamp from first 16 bytes of nonce
    const decoder = new TextDecoder();
    const timestampBytes = nonce.slice(0, 16);
    const timestampStr = decoder.decode(timestampBytes).replace(/^0+/, "");
    const timestamp = parseInt(timestampStr, 10);

    if (isNaN(timestamp)) {
      return { valid: false, error: "Invalid timestamp in nonce" };
    }

    // Check if nonce is expired
    const age = Date.now() - timestamp;
    if (age > maxAge) {
      return { valid: false, error: "Nonce has expired" };
    }

    return { valid: true };
  } catch (error) {
    return {
      valid: false,
      error:
        error instanceof Error
          ? error.message
          : "Unknown error validating nonce",
    };
  }
}
