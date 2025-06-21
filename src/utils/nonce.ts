import { NonceType } from "../types.js";

/**
 * Default max age for nonce validation (24 hours in milliseconds)
 */

const DEFAULT_MAX_AGE = 24 * 60 * 60 * 1000;

function isBuffer(obj: any): boolean {
  return (
    typeof Buffer !== "undefined" &&
    obj !== null &&
    typeof obj === "object" &&
    Buffer.isBuffer(obj)
  );
}

export function ensureUint8Array(nonce: NonceType): Uint8Array {
  let bytes: Uint8Array;

  if (nonce instanceof Uint8Array) {
    bytes = nonce;
    // If it's already exactly 32 bytes, return it directly
    if (bytes.length === 32) {
      return bytes;
    }
  } else if (isBuffer(nonce)) {
    bytes = new Uint8Array(nonce as any);
  } else if (typeof nonce === "string") {
    const encoder = new TextEncoder();
    bytes = encoder.encode(nonce);
  } else if (typeof nonce === "number") {
    const encoder = new TextEncoder();
    bytes = encoder.encode(nonce.toString());
  } else {
    throw new Error("Unsupported nonce type");
  }

  // Pad or truncate to 32 bytes for all types
  return padToLength(bytes, 32);
}

function padToLength(array: Uint8Array, length: number): Uint8Array {
  if (array.length >= length) {
    return array.slice(0, length);
  }
  const result = new Uint8Array(length);
  result.set(array);
  return result;
}

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
 * @throws Error if nonce is invalid
 */
export function validateNonce(
  nonce: Uint8Array,
  maxAge: number = DEFAULT_MAX_AGE,
): void {
  try {
    // Check nonce length
    if (nonce.length !== 32) {
      throw new Error("Invalid nonce length");
    }

    // Extract timestamp from first 16 bytes of nonce
    const decoder = new TextDecoder();
    const timestampBytes = nonce.slice(0, 16);
    const timestampStr = decoder.decode(timestampBytes).replace(/^0+/, "");
    const timestamp = parseInt(timestampStr, 10);

    if (isNaN(timestamp)) {
      throw new Error("Invalid timestamp in nonce");
    }

    // Check if nonce is expired or from the future
    const age = Date.now() - timestamp;
    if (age < 0) {
      throw new Error("Nonce timestamp is in the future");
    }
    if (age > maxAge) {
      throw new Error("Nonce has expired");
    }
  } catch (error) {
    if (error instanceof Error) {
      throw error;
    }
    throw new Error("Unknown error validating nonce");
  }
}
