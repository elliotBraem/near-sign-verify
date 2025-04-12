import type { ValidationResult } from "../types.js";

/**
 * Generate a nonce for signing
 * @returns A nonce string
 */
export function generateNonce(): string {
  return Date.now().toString();
}

/**
 * Validate a nonce
 * @param nonce Nonce string
 * @returns Validation result
 */
export function validateNonce(nonce: string): ValidationResult {
  try {
    // Convert to timestamp and validate
    const nonceInt = parseInt(nonce);
    const now = Date.now();

    if (isNaN(nonceInt)) {
      return { valid: false, error: "Invalid nonce format" };
    }

    if (nonceInt > now) {
      return { valid: false, error: "Nonce is in the future" };
    }

    // If the timestamp is older than 10 years, it is considered invalid
    // This forces apps to use unique nonces
    if (now - nonceInt > 10 * 365 * 24 * 60 * 60 * 1000) {
      return { valid: false, error: "Nonce is too old" };
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
