import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import * as borsh from "borsh";
import type { SignedPayload } from "../types.js"; // Updated import
import { fromBase58 } from "@fastnear/utils";

export const ED25519_PREFIX = "ed25519:";
export const TAG = 2147484061; // 2**31 + 413

/**
 * Borsh schema for the NEP-413 SignedPayload.
 * This structure (message, nonce, recipient, callbackUrl) is what gets serialized,
 * then prepended with the serialized TAG, and then hashed.
 */
const signedPayloadBorshSchema = {
  struct: {
    message: "string",
    nonce: { array: { type: "u8", len: 32 } },
    recipient: "string",
    callbackUrl: { option: "string" },
  },
};

/**
 * Hashes a payload according to NEP-413 specification for signing.
 * This involves:
 * 1. Serializing the TAG (u32, little-endian).
 * 2. Serializing the `SignedPayload` (message, nonce, recipient, callbackUrl) using Borsh.
 * 3. Concatenating `serializedTag + serializedSignedPayload`.
 * 4. Computing the SHA-256 hash of the concatenated bytes.
 * @param tag The NEP-413 tag (e.g., 2**31 + 413).
 * @param payload The `SignedPayload` object.
 * @returns The SHA-256 hash as a Uint8Array.
 */
export function hashForSigning(
  tag: number,
  payload: SignedPayload,
): Uint8Array {
  // 1. Serialize the TAG (as u32, little-endian)
  const tagBytes = new Uint8Array(4);
  new DataView(tagBytes.buffer).setUint32(0, tag, true); // true for little-endian

  // 2. Serialize the SignedPayload
  // Borsh expects nonce as ArrayLike<number>, ensure Uint8Array is converted if necessary by schema or here.
  // The schema { array: { type: "u8", len: 32 } } should handle Uint8Array directly.
  // Ensure optional callbackUrl is null if undefined for Borsh.
  const borshCompatiblePayload = {
    message: payload.message,
    nonce: payload.nonce, // Schema should handle Uint8Array
    recipient: payload.recipient,
    callbackUrl: payload.callbackUrl ?? null,
  };
  const serializedSignedPayload = borsh.serialize(
    signedPayloadBorshSchema,
    borshCompatiblePayload,
  );

  // 3. Concatenate them
  const bytesToHash = new Uint8Array(
    tagBytes.length + serializedSignedPayload.length,
  );
  bytesToHash.set(tagBytes, 0);
  bytesToHash.set(serializedSignedPayload, tagBytes.length);

  // 4. Compute SHA-256 hash
  return sha256(bytesToHash);
}

// --- Old functions - potentially deprecated if no longer used by the new signing flow ---
// /**
//  * @deprecated This function serializes a payload structure that includes the tag internally.
//  * NEP-413 requires the tag to be prepended to the serialized payload.
//  * Consider using logic within `hashForSigning` for NEP-413 compliant serialization.
//  */
// export function serializePayload(payload: NearAuthPayload): Uint8Array {
//   const borshPayload = {
//     tag: payload.tag,
//     message: payload.message,
//     nonce: Array.from(payload.nonce),
//     receiver: payload.receiver,
//     callback_url: payload.callback_url || null,
//   };

//   const schema = {
//     struct: {
//       tag: "u32",
//       message: "string",
//       nonce: { array: { type: "u8", len: 32 } },
//       receiver: "string",
//       callback_url: { option: "string" },
//     },
//   };

//   return borsh.serialize(schema, borshPayload);
// }

// /**
//  * @deprecated This function hashes a pre-serialized payload.
//  * For NEP-413, use `hashForSigning` which handles the specific NEP-413 hashing process.
//  */
// export function hashPayload(payload: Uint8Array): Uint8Array {
//   return sha256(payload);
// }
// --- End of old functions ---

/**
 * Verify a signature against a pre-computed payload hash.
 * Throws an error if verification fails or encounters an issue.
 * @param payloadHash The hash of the payload that was signed.
 * @param signatureBytes The raw signature bytes to verify.
 * @param publicKeyString The public key string (e.g., "ed25519:...") to verify against.
 */
export async function verifySignature(
  payloadHash: Uint8Array,
  signatureBytes: Uint8Array,
  publicKeyString: string,
): Promise<boolean> {
  if (publicKeyString.startsWith(ED25519_PREFIX)) {
    const isValid = ed25519.verify(
      signatureBytes,
      payloadHash,
      fromBase58(publicKeyString.split(":")[1]),
    );
    if (!isValid) {
      throw new Error("Ed25519 signature verification failed.");
    }
    return true;
  } else {
    throw new Error(
      `Unsupported public key type: "${publicKeyString}". Must start with "${ED25519_PREFIX}".`,
    );
  }
}
