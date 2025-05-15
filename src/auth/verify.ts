import bs58 from "bs58";
import { base64ToUint8Array } from "../utils/encoding.js";
import { validateNonce } from "../utils/nonce.js";
import { ED25519_PREFIX, verifySignature } from "../crypto/crypto.js";
import type { ValidationResult, NearAuthData } from "../types.js";

/**
 * Options for the verify function.
 */
export interface VerifyOptions {
  /**
   * Whether the public key must be a full access key.
   * Defaults to true.
   */
  requireFullAccessKey?: boolean;
  /**
   * Maximum age of the nonce in milliseconds.
   * If not provided, validateNonce will use its internal default (e.g., 24 hours).
   */
  nonceMaxAge?: number;
}

// Verifies public key ownership via FastNEAR
async function verifyPublicKeyOwner(
  accountId: string,
  publicKey: string,
  requireFullAccessKey: boolean,
): Promise<{ success: boolean; apiFailure?: boolean }> {
  const isTestnet = accountId.endsWith(".testnet");
  const baseUrl = isTestnet
    ? "https://test.api.fastnear.com"
    : "https://api.fastnear.com";
  const pathSuffix = requireFullAccessKey ? "" : "/all";
  const url = `${baseUrl}/v0/public_key/${publicKey}${pathSuffix}`;

  try {
    const response = await fetch(url);
    if (!response.ok) {
      return { success: false, apiFailure: true };
    }
    const data = await response.json();
    if (data && Array.isArray(data.account_ids)) {
      if (data.account_ids.includes(accountId)) {
        return { success: true };
      }
      return { success: false, apiFailure: false }; // API success, but accountId not found
    }
    return { success: false, apiFailure: true }; // Unexpected API response format
  } catch (error) {
    return { success: false, apiFailure: true }; // Network error or JSON parsing error
  }
}

/**
 * Verifies NEAR authentication data, including nonce, public key ownership, and cryptographic signature.
 * @param authData The NEAR authentication data.
 * @param options Optional verification parameters.
 * @returns A promise that resolves to a ValidationResult.
 */
export async function verify(
  authData: NearAuthData,
  options?: VerifyOptions,
): Promise<ValidationResult> {
  const {
    account_id: accountId,
    public_key: publicKey,
    signature,
    message,
    nonce,
    recipient,
  } = authData;

  const requireFullAccessKey = options?.requireFullAccessKey ?? true;
  const nonceMaxAge = options?.nonceMaxAge;

  try {
    const nonceValidation = validateNonce(nonce, nonceMaxAge);
    if (!nonceValidation.valid) {
      return nonceValidation;
    }

    const ownerCheckResult = await verifyPublicKeyOwner(
      accountId,
      publicKey,
      requireFullAccessKey,
    );

    if (!ownerCheckResult.success) {
      if (ownerCheckResult.apiFailure) {
        return {
          valid: false,
          error: "Failed to verify public key ownership with external API.",
        };
      }
      return {
        valid: false,
        error:
          "Public key does not belong to the specified account or does not meet access requirements.",
      };
    }

    const signatureBytes = base64ToUint8Array(signature);
    const publicKeyString = publicKey.startsWith(ED25519_PREFIX)
      ? publicKey.substring(ED25519_PREFIX.length)
      : publicKey;
    const publicKeyBytes = bs58.decode(publicKeyString);

    try {
      const isValidCryptoSignature = await verifySignature(
        message,
        signatureBytes,
        publicKeyBytes,
        nonce,
        recipient,
      );

      return {
        valid: isValidCryptoSignature,
        error: isValidCryptoSignature
          ? undefined
          : "Invalid signature",
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
          : "Unknown error during verification process",
    };
  }
}
