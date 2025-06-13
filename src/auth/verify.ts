import { base64ToUint8Array } from "../utils/encoding.js";
import { validateNonce as defaultNonceValidator } from "../utils/nonce.js";
import { verifySignature, hashForSigning, TAG } from "../crypto/crypto.js";
import type {
  NearAuthTokenPayload,
  VerifyOptions,
  VerificationResult,
  SignedPayload,
} from "../types.js";
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
      // Consider logging response.status and response.statusText for better debugging
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
    // Consider logging the error
    return { success: false, apiFailure: true }; // Network error or JSON parsing error
  }
}

/**
 * Verifies a NEAR authentication token string.
 * This includes parsing the token, validating various components like nonce, recipient, state,
 * public key ownership, and the cryptographic signature against the NEP-413 specified payload.
 * Throws an error if verification fails at any step.
 * @param authTokenString The Base64 encoded, Borsh-serialized NearAuthTokenPayload string.
 * @param options Optional verification parameters.
 * @returns A promise that resolves to VerificationResult if successful.
 */
export async function verify<TMessage = any>(
  authTokenString: string,
  options?: VerifyOptions<TMessage>,
): Promise<VerificationResult<TMessage>> {
  let tokenData: NearAuthTokenPayload;
  try {
    tokenData = parseAuthToken(authTokenString);
  } catch (e: any) {
    throw new Error(`Failed to parse auth token: ${e.message}`);
  }

  const {
    account_id: accountId,
    public_key: publicKey,
    signature: signatureB64,
    signed_message_content: signedMessageContent,
    signed_nonce: signedNonce,
    signed_recipient: signedRecipient,
    signed_callback_url: signedCallbackUrl,
    state: tokenState,
    original_message_representation: originalMessageRepresentation,
  } = tokenData;

  // 1. Nonce validation
  if (options?.validateNonce) {
    if (!options.validateNonce(signedNonce)) {
      throw new Error("Custom nonce validation failed.");
    }
  } else {
    try {
      defaultNonceValidator(signedNonce, options?.nonceMaxAge);
    } catch (error) {
      throw new Error(
        `Default nonce validation failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }

  // 2. Recipient validation
  if (options?.expectedRecipient || options?.validateRecipient) {
    let recipientValid = false;
    if (options.expectedRecipient && signedRecipient === options.expectedRecipient) {
      recipientValid = true;
    }
    if (!recipientValid && options.validateRecipient) {
      if (options.validateRecipient(signedRecipient)) {
        recipientValid = true;
      }
    }
    if (!recipientValid) {
      throw new Error(
        `Recipient validation failed. Expected: '${
          options.expectedRecipient ?? "N/A"
        }', Custom validation: ${
          options.validateRecipient ? "failed" : "not provided"
        }, Actual: '${signedRecipient}'.`,
      );
    }
  } else {
    // If no recipient validation options are provided, it's a good practice to warn or require one.
    // For now, we'll proceed, but this could be a configurable policy.
    console.warn("Warning: No recipient validation (expectedRecipient or validateRecipient) was provided. This is a security risk.");
  }


  // 3. State validation
  if (options?.expectedState || options?.validateState) {
    let stateValid = false;
    if (options.expectedState && tokenState === options.expectedState) {
      stateValid = true;
    }
    if (!stateValid && options.validateState) {
      if (options.validateState(tokenState ?? undefined)) { // Pass undefined if null
        stateValid = true;
      }
    }
    if (!stateValid) {
      throw new Error(
        `State validation failed. Expected: '${
          options.expectedState ?? "N/A"
        }', Custom validation: ${
          options.validateState ? "failed" : "not provided"
        }, Actual: '${tokenState ?? "undefined"}'.`,
      );
    }
  }
  // If no state validation is provided, it's fine as state is optional.

  // 4. Public Key Ownership
  const requireFullAccessKey = options?.requireFullAccessKey ?? true;
  const ownerCheckResult = await verifyPublicKeyOwner(
    accountId,
    publicKey,
    requireFullAccessKey,
  );

  if (!ownerCheckResult.success) {
    const reason = ownerCheckResult.apiFailure
      ? "API error or unexpected response during public key ownership check"
      : "public key not associated with the account or does not meet access key requirements";
    throw new Error(`Public key ownership verification failed: ${reason}.`);
  }

  // 5. Cryptographic Signature Verification
  // Reconstruct the payload that was originally signed according to NEP-413
  const payloadForVerification: SignedPayload = {
    message: signedMessageContent,
    nonce: signedNonce,
    recipient: signedRecipient,
    callbackUrl: signedCallbackUrl || undefined,
  };

  const payloadHash = hashForSigning(TAG, payloadForVerification);
  const signatureBytes = base64ToUint8Array(signatureB64);

  try {
    await verifySignature(payloadHash, signatureBytes, publicKey);
  } catch (error) {
    throw new Error(
      `Cryptographic signature verification failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  // 6. Parse the original message
  let parsedMessage: TMessage;
  const messageToParse = originalMessageRepresentation ?? signedMessageContent;

  if (options?.messageParser) {
    try {
      parsedMessage = options.messageParser(messageToParse);
    } catch (e) {
      throw new Error(
        `Failed to parse message using custom parser: ${
          e instanceof Error ? e.message : String(e)
        }`,
      );
    }
  } else {
    if (originalMessageRepresentation) { // Implies original was not string
      try {
        parsedMessage = JSON.parse(messageToParse) as TMessage;
      } catch (e) {
        throw new Error(
          `Failed to parse original_message_representation as JSON: ${
            e instanceof Error ? e.message : String(e)
          }. Original representation: "${messageToParse}"`,
        );
      }
    } else { // Original was string, or no specific representation stored
      parsedMessage = messageToParse as unknown as TMessage;
    }
  }

  return {
    accountId: accountId,
    publicKey: publicKey,
    message: parsedMessage,
    callbackUrl: signedCallbackUrl || undefined,
    state: tokenState || undefined,
  };
}
