import bs58 from "bs58";
import { base64ToUint8Array } from "../utils/encoding.js";
import { validateNonce } from "../utils/nonce.js";
import { ED25519_PREFIX, verifySignature } from "../crypto/crypto.js";
import type { ValidationResult, NearAuthData } from "../types.js";

/**
 * Validate a NEAR signature
 * @param authData NEAR authentication data
 * @returns Validation result
 */
export async function validateSignature(
  authData: NearAuthData,
): Promise<ValidationResult> {
  const {
    signature,
    message,
    public_key: publicKey,
    nonce,
    recipient,
  } = authData;
  try {
    const nonceValidation = validateNonce(nonce);
    if (!nonceValidation.valid) {
      return nonceValidation;
    }

    // Decode the signature
    const signatureBytes = base64ToUint8Array(signature);

    // Decode the public key (remove ed25519: prefix if present)
    const publicKeyString = publicKey.startsWith(ED25519_PREFIX)
      ? publicKey.substring(ED25519_PREFIX.length)
      : publicKey;

    // Use bs58 to decode the public key
    const publicKeyBytes = bs58.decode(publicKeyString);

    try {
      const isValid = await verifySignature(
        message,
        signatureBytes,
        publicKeyBytes,
        nonce,
        recipient,
      );

      return {
        valid: isValid,
        error: isValid ? undefined : "Invalid signature",
      };
    } catch (error) {
      return {
        valid: false,
        error:
          error instanceof Error
            ? error.message
            : "Unknown error validating signature",
      };
    }
  } catch (error) {
    return {
      valid: false,
      error:
        error instanceof Error
          ? error.message
          : "Unknown error validating signature",
    };
  }
}
