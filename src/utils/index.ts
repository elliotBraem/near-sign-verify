/**
 * Utility functions for NEAR Simple Signing
 */

import type { ValidationResult } from '../types.ts';

/**
 * Generate a nonce for signing
 * @returns A nonce string
 */
export function generateNonce(): string {
  return Date.now().toString();
}

/**
 * Convert a string to Uint8Array
 * @param str String to convert
 * @returns Uint8Array
 */
export function stringToUint8Array(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Convert Uint8Array to string
 * @param arr Uint8Array to convert
 * @returns String
 */
export function uint8ArrayToString(arr: Uint8Array): string {
  return new TextDecoder().decode(arr);
}

/**
 * Convert base64 string to Uint8Array
 * @param base64 Base64 string
 * @returns Uint8Array
 */
export function base64ToUint8Array(base64: string): Uint8Array {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

/**
 * Convert Uint8Array to base64 string
 * @param arr Uint8Array to convert
 * @returns Base64 string
 */
export function uint8ArrayToBase64(arr: Uint8Array): string {
  return btoa(String.fromCharCode.apply(null, Array.from(arr)));
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
      return { valid: false, error: 'Invalid nonce format' };
    }

    if (nonceInt > now) {
      return { valid: false, error: 'Nonce is in the future' };
    }

    // If the timestamp is older than 10 years, it is considered invalid
    // This forces apps to use unique nonces
    if (now - nonceInt > 10 * 365 * 24 * 60 * 60 * 1000) {
      return { valid: false, error: 'Nonce is too old' };
    }

    return { valid: true };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Unknown error validating nonce',
    };
  }
}

/**
 * Create a properly formatted auth header for the Crosspost API
 * @param authData NEAR authentication data
 * @returns Auth header string
 */
export function createAuthHeader(authData: {
  account_id: string;
  public_key: string;
  signature: string;
  message: string;
  nonce: string;
  recipient?: string;
  callback_url?: string;
}): string {
  return JSON.stringify(authData);
}
