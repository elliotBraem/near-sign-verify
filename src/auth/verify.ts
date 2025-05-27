import { base64ToUint8Array, uint8ArrayToBase64 } from "../utils/encoding.js";
import { validateNonce } from "../utils/nonce.js";
import {
  verifySignature,
  serializePayload,
  hashPayload,
  TAG,
} from "../crypto/crypto.js";
import type {
  NearAuthData,
  NearAuthPayload,
  VerifyOptions,
  VerificationResult,
  MessageData,
} from "../types.js";
import { parseAuthToken } from "./parseAuthToken.js";

async function verifyPublicKeyOwner(
  accountId: string,
  publicKey: string,
  requireFullAccessKey: boolean
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
  options?: VerifyOptions
): Promise<VerificationResult> {
  let authData: NearAuthData;
  try {
    authData = parseAuthToken(authTokenString);
  } catch (e: any) {
    throw new Error(`Failed to parse auth token: ${e.message}`);
  }

  const {
    account_id: accountId,
    public_key: publicKeyString,
    signature: signatureB64,
    message: messageString, // JSON string of MessageData
    nonce: nonceFromAuthData, // nonce from the NearAuthPayload
    recipient: recipientFromAuthData,
    callback_url,
  } = authData;

  // Validate and parse message structure from messageString
  let messageData: MessageData;
  try {
    const parsed = JSON.parse(messageString);
    if (
      typeof parsed.nonce !== "string" ||
      typeof parsed.timestamp !== "number" ||
      typeof parsed.recipient !== "string"
    ) {
      throw new Error(
        "Invalid message structure: missing or invalid nonce, timestamp, or recipient."
      );
    }
    const allowedFields = ["nonce", "timestamp", "recipient", "data"];
    const extraFields = Object.keys(parsed).filter(
      (key) => !allowedFields.includes(key)
    );
    if (extraFields.length > 0) {
      throw new Error(
        `Unexpected fields in message: ${extraFields.join(", ")}`
      );
    }
    messageData = parsed as MessageData;
  } catch (e: any) {
    throw new Error(`Invalid message format in token: ${e.message}`);
  }

  // Validate timestamp is reasonable
  const now = Date.now();
  const timeDiff = Math.abs(now - messageData.timestamp);
  // Default max age for timestamp diff can be, e.g., 24 hours, or configurable
  const maxTimestampDiff = 24 * 60 * 60 * 1000;
  if (timeDiff > maxTimestampDiff) {
    throw new Error(
      `Message timestamp too far from current time (diff: ${timeDiff}ms, max: ${maxTimestampDiff}ms)`
    );
  }

  // Nonce validation
  if (options && "validateNonce" in options && options.validateNonce) {
    // Custom nonce validation
    if (!options.validateNonce(messageData)) {
      throw new Error("Custom nonce validation failed.");
    }
  } else {
    // Standard nonce validation using nonce from AuthData (which was part of the signed payload)
    try {
      validateNonce(nonceFromAuthData, options?.nonceMaxAge);
    } catch (error) {
      throw new Error(`Nonce validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Cross-validate messageData fields with authData fields
  if (messageData.recipient !== recipientFromAuthData) {
    throw new Error(
      `Recipient mismatch: message recipient '${messageData.recipient}' vs signed payload recipient '${recipientFromAuthData}'.`
    );
  }
  if (uint8ArrayToBase64(nonceFromAuthData) !== messageData.nonce) {
    throw new Error(
      "Nonce mismatch: message nonce vs signed payload nonce."
    );
  }

  // Validate expected recipient if provided
  if (
    options?.expectedRecipient &&
    messageData.recipient !== options.expectedRecipient
  ) {
    throw new Error(
      `Recipient mismatch: expected '${options.expectedRecipient}', but message recipient is '${messageData.recipient}'.`
    );
  }

  const requireFullAccessKey = options?.requireFullAccessKey ?? true;
  const ownerCheckResult = await verifyPublicKeyOwner(
    accountId,
    publicKeyString,
    requireFullAccessKey
  );

  if (!ownerCheckResult.success) {
    // Provide more context if API failed vs. accountId not found
    const reason = ownerCheckResult.apiFailure
      ? "API error or unexpected response"
      : "public key not associated with the account or does not meet access key requirements";
    throw new Error(`Public key ownership verification failed: ${reason}.`);
  }

  // Reconstruct the payload that was originally signed
  const payloadToVerify: NearAuthPayload = {
    tag: TAG,
    message: messageString, // The original JSON string of MessageData
    nonce: nonceFromAuthData, // The nonce that was part of the signed payload
    receiver: recipientFromAuthData, // The recipient that was part of the signed payload
    callback_url: callback_url || undefined,
  };

  const serializedPayloadToVerify = serializePayload(payloadToVerify);
  const payloadHash = hashPayload(serializedPayloadToVerify);
  const signatureBytes = base64ToUint8Array(signatureB64);

  try {
    await verifySignature(
      payloadHash,
      signatureBytes,
      publicKeyString
    );
  } catch (error) {
    throw new Error(
      `Cryptographic signature verification failed: ${
        error instanceof Error ? error.message : String(error)
      }`
    );
  }

  return {
    accountId: accountId,
    messageData: messageData,
    publicKey: publicKeyString,
    callbackUrl: callback_url || undefined,
  };
}
