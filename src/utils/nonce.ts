import type { ValidationResult } from "../types.js";
import { uint8ArrayToBase64 } from "./encoding.js";

/**
 * Generate a nonce for signing
 * @returns A nonce string
 */
export function generateNonce(): string {
  const randomBytes = crypto.getRandomValues(new Uint8Array(16));
  return uint8ArrayToBase64(randomBytes);
}

/**
 * Validate a nonce
 * @param nonce Nonce string
 * @returns Validation result
 */
export function validateNonce(nonce: string): ValidationResult {
  try {
    // Check if nonce has proper format
    if (!/^[A-Za-z0-9+/=]+$/.test(nonce)) {
      return { valid: false, error: "Invalid nonce format" };
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
