import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { base58 } from "@scure/base";
import { b } from "@zorsh/zorsh";
import { SignedPayloadSchema } from "../schemas.js";
import type { SignedPayload } from "../types.js";

export const ED25519_PREFIX = "ed25519:";
export const TAG = 2147484061;

/**
 * Create a NEP-413 payload to be hashed
 * (Serialize the TAG and the payload separately, then concatenate)
 * @param payload Payload to serialize
 * @returns Concatenated, serialized payloads as Uint8Array
 */
export function createNEP413Payload(payload: SignedPayload): Uint8Array {
  const serializedTag = b.u32().serialize(TAG);

  const serializablePayload = {
    // Convert nonce from Uint8Array to number[] for zorsh
    ...payload,
    nonce: Array.from(payload.nonce),
    callbackUrl: payload.callbackUrl || null,
  };
  const serializedPayload = SignedPayloadSchema.serialize(serializablePayload);

  const dataToHash = new Uint8Array(
    serializedTag.length + serializedPayload.length,
  );
  dataToHash.set(serializedTag, 0);
  dataToHash.set(serializedPayload, serializedTag.length);

  return dataToHash;
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
export async function verifySignature( // remove async, update tests
  payloadHash: Uint8Array,
  signatureBytes: Uint8Array,
  publicKeyString: string,
): Promise<boolean> {
  if (publicKeyString.startsWith(ED25519_PREFIX)) {
    const isValid = ed25519.verify(
      signatureBytes,
      payloadHash,
      base58.decode(publicKeyString.split(":")[1]),
    );
    if (!isValid) {
      throw new Error("Ed25519 signature verification failed.");
    }
    return true;
  }

  throw new Error(
    `Unsupported public key type: "${publicKeyString}". Must start with "${ED25519_PREFIX}".`,
  );
}
