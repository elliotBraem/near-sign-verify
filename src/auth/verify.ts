import { base64 } from "@scure/base";
import {
  createNEP413Payload,
  hashPayload,
  verifySignature,
} from "../crypto/crypto.js";
import type {
  NearAuthData,
  NonceType,
  SignedPayload,
  VerificationResult,
  VerifyOptions,
} from "../types.js";
import { ensureUint8Array, validateNonce } from "../utils/nonce.js";
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
export async function verify<TNonce extends NonceType = Uint8Array>(
  authTokenString: string,
  options?: VerifyOptions<TNonce>,
): Promise<VerificationResult> {
  let authData: NearAuthData;
  try {
    authData = parseAuthToken(authTokenString);
  } catch (e: any) {
    throw new Error(`Failed to parse auth token: ${e.message}`);
  }

  const {
    accountId,
    publicKey,
    signature: signatureB64,
    message: messageString,
    nonce: nonceFromAuthData, // nonce from NearAuthData as number[]
    recipient: recipientFromAuthData,
    callbackUrl,
    state,
  } = authData;

  // Convert number[] back to Uint8Array
  const nonce = new Uint8Array(nonceFromAuthData);

  // Validate nonce
  if (options?.validateNonce) {
    // For custom validation, pass the nonce as the original type
    if (!options.validateNonce(nonce)) {
      throw new Error("Custom nonce validation failed.");
    }
  } else {
    // Standard nonce validation using nonce from AuthData (which was part of the signed payload)
    try {
      validateNonce(ensureUint8Array(nonce), options?.nonceMaxAge);
    } catch (error) {
      throw new Error(
        `Nonce validation failed: ${error instanceof Error ? error.message : "Unknown error"}`,
      );
    }
  }

  // Validate recipient
  if (options?.validateRecipient) {
    if (!options.validateRecipient(recipientFromAuthData)) {
      throw new Error("Custom recipient validation failed.");
    }
  } else if (options && typeof options.expectedRecipient === "string") {
    if (recipientFromAuthData !== options.expectedRecipient) {
      throw new Error(
        `Recipient mismatch: expected '${options.expectedRecipient}', but recipient is '${recipientFromAuthData}'.`,
      );
    }
  }

  // Validate state
  if (options?.validateState) {
    if (!options.validateState(state!)) {
      throw new Error("Custom state validation failed.");
    }
  } else if (options && typeof options.expectedState === "string") {
    if (state !== options.expectedState) {
      throw new Error(
        `State mismatch: expected '${options.expectedState}', got '${state?.toString() || "undefined"}'.`,
      );
    }
  }

  // Validate message
  if (options?.validateMessage) {
    if (!options.validateMessage(messageString)) {
      throw new Error("Custom message validation failed.");
    }
  } else if (options && typeof options.expectedMessage === "string") {
    if (messageString !== options.expectedMessage) {
      throw new Error(
        `Message mismatch: expected '${options.expectedMessage}', got '${messageString}'.`,
      );
    }
  }

  // Validate publicKey
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
  const nep413PayloadToVerify: SignedPayload = {
    message: messageString,
    nonce: Array.from(nonce),
    recipient: recipientFromAuthData,
    callbackUrl,
  };

  const dataThatWasHashed = createNEP413Payload(nep413PayloadToVerify);

  const payloadHash = hashPayload(dataThatWasHashed);
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
    callbackUrl: callbackUrl || undefined,
    state: state || undefined,
  };
}
