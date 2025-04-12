import * as borsh from "borsh";
import nacl from "tweetnacl";
import type { NearAuthPayload } from "../types.js";
import { stringToUint8Array } from "../utils/encoding.js";

export const ED25519_PREFIX = "ed25519:";
export const TAG = 2147484061;

/**
 * Pad a nonce to 32 bytes
 * @param nonce Nonce string
 * @returns Padded nonce as Uint8Array
 */
export function padNonce(nonce: string): Uint8Array {
  const paddedNonce = nonce.padStart(32, "0");
  return stringToUint8Array(paddedNonce);
}

/**
 * Serialize a payload using Borsh
 * @param payload Payload to serialize
 * @returns Serialized payload as Uint8Array
 */
export function serializePayload(payload: NearAuthPayload): Uint8Array {
  const borshPayload = {
    tag: payload.tag,
    message: payload.message,
    nonce: Array.from(payload.nonce), // Convert Uint8Array to array for serialization
    receiver: payload.receiver,
    callback_url: payload.callback_url || null,
  };

  // Can we sync this borsch schema with rust types?
  const schema = {
    struct: {
      tag: "u32",
      message: "string",
      nonce: { array: { type: "u8", len: 32 } },
      receiver: "string",
      callback_url: { option: "string" },
    },
  };

  return borsh.serialize(schema, borshPayload);
}

/**
 * Hash a payload
 * @param payload Payload to hash
 * @returns Hashed payload as Uint8Array
 */
export async function hashPayload(payload: Uint8Array): Promise<Uint8Array> {
  try {
    // Try to use the Web Crypto API first (works in modern browsers and Node.js)
    if (typeof crypto !== "undefined" && crypto.subtle) {
      const hashBuffer = await crypto.subtle.digest("SHA-256", payload);
      return new Uint8Array(hashBuffer);
    }

    // Fallback to Node.js crypto if available
    try {
      const nodeCrypto = await import("node:crypto");
      const hash = nodeCrypto.createHash("sha256");
      hash.update(new Uint8Array(payload));
      return new Uint8Array(hash.digest());
    } catch (e) {
      // If neither is available, use a fallback implementation
      console.warn(
        "Crypto API not available, using fallback hash implementation",
      );
      return fallbackHash(payload);
    }
  } catch (error) {
    console.warn("Error using crypto API, falling back to simple hash", error);
    return fallbackHash(payload);
  }
}

/**
 * Fallback hash implementation for environments without crypto
 * @param payload Payload to hash
 * @returns Hashed payload as Uint8Array
 */
function fallbackHash(payload: Uint8Array): Uint8Array {
  // let's find a solution to delete this fallback
  const result = new Uint8Array(32);
  for (let i = 0; i < payload.length; i++) {
    result[i % 32] = (result[i % 32] + payload[i]) % 256;
  }
  return result;
}

/**
 * Verify a signature
 * @param message The message that was signed
 * @param signature The signature to verify
 * @param publicKey The public key to verify against
 * @param nonce The nonce used for signing
 * @param recipient The recipient of the message
 * @returns Whether the signature is valid
 */
export async function verifySignature(
  message: string,
  signature: Uint8Array,
  publicKey: Uint8Array,
  nonce: Uint8Array,
  recipient: string,
): Promise<boolean> {
  try {
    const payload: NearAuthPayload = {
      tag: TAG,
      message,
      nonce: new Uint8Array(nonce),
      receiver: recipient,
    };

    const serializedPayload = serializePayload(payload);

    const payloadHash = await hashPayload(serializedPayload);

    return nacl.sign.detached.verify(payloadHash, signature, publicKey);
  } catch (error) {
    console.error("Error verifying signature:", error);
    return false;
  }
}
