import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import * as borsh from "borsh";
import type { NearAuthPayload } from "../types.js";
import { fromBase58 } from "@fastnear/utils";

export const ED25519_PREFIX = "ed25519:";
export const TAG = 2147484061;

/**
 * Serialize a payload using Borsh
 * @param payload Payload to serialize
 * @returns Serialized payload as Uint8Array
 */
export function serializePayload(payload: NearAuthPayload): Uint8Array {
  const borshPayload = {
    tag: payload.tag,
    message: payload.message,
    nonce: Array.from(payload.nonce),
    receiver: payload.receiver,
    callback_url: payload.callback_url || null,
  };

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
 * Hash a payload using SHA-256
 * @param payload Payload to hash
 * @returns Hashed payload as Uint8Array
 */
export function hashPayload(payload: Uint8Array): Uint8Array {
  return sha256(payload);
}

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
