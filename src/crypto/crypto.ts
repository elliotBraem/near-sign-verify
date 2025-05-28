import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import * as borsh from "borsh";
import { PublicKey } from "@near-js/crypto";
import secp256k1 from "secp256k1";
import type { NearAuthPayload } from "../types.js";

export const ED25519_PREFIX = "ed25519:";
export const SECP256K1_PREFIX = "secp256k1:";
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
  publicKeyString: string
): Promise<boolean> {
  let nearPublicKey: PublicKey;
  try {
    nearPublicKey = PublicKey.fromString(publicKeyString);
  } catch (error) {
    throw new Error(
      `Failed to parse public key "${publicKeyString}": ${error instanceof Error ? error.message : String(error)
      }`
    );
  }

  if (publicKeyString.startsWith(ED25519_PREFIX)) {
    const isValid = ed25519.verify(
      signatureBytes,
      payloadHash,
      nearPublicKey.data
    );
    if (!isValid) {
      throw new Error("Ed25519 signature verification failed.");
    }
    return true;
  } else if (publicKeyString.startsWith(SECP256K1_PREFIX)) {
    // near-api-js PublicKey.data for secp256k1 is 64 bytes (x, y).
    // secp256k1.ecdsaVerify expects a 65-byte uncompressed key (0x04 + x + y)
    // or a 33-byte compressed key.
    // We will construct the 65-byte uncompressed key.
    let publicKeyBytes = nearPublicKey.data;
    if (publicKeyBytes.length === 64) {
      publicKeyBytes = Buffer.concat([Buffer.from([0x04]), publicKeyBytes]);
    } else if (publicKeyBytes.length !== 33 && publicKeyBytes.length !== 65) {
      throw new Error(
        `Invalid secp256k1 public key length: ${publicKeyBytes.length}. Expected 33, 64, or 65 bytes.`
      );
    }

    // signatureBytes is expected to be the 64-byte DER-encoded signature by default from near-api-js.
    // However, secp256k1.ecdsaVerify expects a 64-byte (r,s) signature.
    // We need to ensure signatureBytes is in the correct (r,s) format.
    // If the signature from NEAR is DER-encoded, it needs to be converted.
    // For now, assuming signatureBytes is already in the 64-byte (r,s) format.
    // If it's DER encoded, secp256k1.signatureImport will be needed.
    // Let's assume it's compact (r,s) for now.
    if (signatureBytes.length !== 64) {
      // If it's a DER signature, it's usually around 70-72 bytes.
      // We might need to parse it or expect a compact signature.
      // For now, strictly expect 64 bytes for (r,s)
      throw new Error(`Invalid secp256k1 signature length: ${signatureBytes.length}. Expected 64 bytes for (r,s) format.`);
    }

    const isValid = secp256k1.ecdsaVerify(
      signatureBytes, // 64-byte (r,s)
      payloadHash,    // 32-byte hash
      publicKeyBytes  // 33-byte compressed or 65-byte uncompressed
    );
    if (!isValid) {
      throw new Error("Secp256k1 signature verification failed.");
    }
    return true;
  } else {
    throw new Error(
      `Unsupported public key type: ${publicKeyString}. Must start with "${ED25519_PREFIX}" or "${SECP256K1_PREFIX}".`
    );
  }
}
