import { base64 } from "@scure/base";
import {
  TAG,
  hashPayload,
  serializePayload,
  verifySignature,
} from "../crypto/crypto.js";
import type {
  NearAuthData,
  NearAuthPayload,
  VerificationResult,
  VerifyOptions,
} from "../types.js";
import { validateNonce } from "../utils/nonce.js";
import { parseAuthToken } from "./parseAuthToken.js";

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
 * Verifies a NEAR authentication token string.
 * This includes parsing the token, validating the message structure,
 * checking nonce, public key ownership, and the cryptographic signature.
 * Throws an error if verification fails at any step.
 * @param authTokenString The Base64 encoded, Borsh-serialized NearAuthData string.
 * @param options Optional verification parameters.
 * @returns A promise that resolves to VerificationResult if successful.
 */
export async function verify(
  authTokenString: string,
  options?: VerifyOptions,
): Promise<VerificationResult> {
  let authData: NearAuthData;
  try {
    authData = parseAuthToken(authTokenString);
  } catch (e: any) {
    throw new Error(`Failed to parse auth token: ${e.message}`);
  }

  const {
    account_id: accountId,
    public_key: publicKey,
    signature: signatureB64,
    message: messageString,
    nonce: nonceFromAuthData, // nonce from the NearAuthPayload
    recipient: recipientFromAuthData,
    callback_url,
  } = authData;

  // Nonce validation - convert number[] back to Uint8Array for validation functions
  const nonceAsUint8Array = new Uint8Array(nonceFromAuthData);

  if (options && "validateNonce" in options && options.validateNonce) {
    // Custom nonce validation
    if (!options.validateNonce(nonceAsUint8Array)) {
      throw new Error("Custom nonce validation failed.");
    }
  } else {
    // Standard nonce validation using nonce from AuthData (which was part of the signed payload)
    try {
      validateNonce(nonceAsUint8Array, options?.nonceMaxAge);
    } catch (error) {
      throw new Error(
        `Nonce validation failed: ${error instanceof Error ? error.message : "Unknown error"}`,
      );
    }
  }

  // Validate expected recipient if provided
  if (
    options?.expectedRecipient &&
    recipientFromAuthData !== options.expectedRecipient
  ) {
    throw new Error(
      `Recipient mismatch: expected '${options.expectedRecipient}', but recipient is '${recipientFromAuthData}'.`,
    );
  }

  const requireFullAccessKey = options?.requireFullAccessKey ?? true;
  const ownerCheckResult = await verifyPublicKeyOwner(
    accountId,
    publicKey,
    requireFullAccessKey,
  );

  if (!ownerCheckResult.success) {
    const reason = ownerCheckResult.apiFailure
      ? "API error or unexpected response"
      : "public key not associated with the account or does not meet access key requirements";
    throw new Error(`Public key ownership verification failed: ${reason}.`);
  }

  // Reconstruct the payload that was originally signed
  const payloadToVerify: NearAuthPayload = {
    tag: TAG,
    message: messageString,
    nonce: nonceFromAuthData, // The nonce that was part of the signed payload
    receiver: recipientFromAuthData, // The recipient that was part of the signed payload
    callback_url: callback_url || null,
  };

  const serializedPayloadToVerify = serializePayload(payloadToVerify);
  const payloadHash = hashPayload(serializedPayloadToVerify);
  const signatureBytes = base64.decode(signatureB64);

  try {
    await verifySignature(payloadHash, signatureBytes, publicKey);
  } catch (error) {
    throw new Error(
      `Cryptographic signature verification failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  return {
    accountId: accountId,
    message: messageString,
    publicKey: publicKey,
    callbackUrl: callback_url || undefined,
  };
}
