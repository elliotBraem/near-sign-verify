import type { NearAuthTokenPayload } from "../types.js";

/**
 * Borsh schema for NearAuthTokenPayload.
 * This is the structure that is serialized and encoded into the final authTokenString.
 */
export const nearAuthTokenPayloadBorshSchema = {
  struct: {
    account_id: "string",
    public_key: "string",
    signature: "string", // Base64 of raw signature

    // Fields that were part of the signed SignedPayload
    signed_message_content: "string",
    signed_nonce: { array: { type: "u8", len: 32 } },
    signed_recipient: "string",
    signed_callback_url: { option: "string" },

    // Additional metadata for the token (not part of the signature hash)
    state: { option: "string" },
    original_message_representation: { option: "string" },
  },
};

/**
 * Helper function to prepare NearAuthTokenPayload data for Borsh serialization,
 * ensuring optional fields are correctly represented (e.g., as null if undefined).
 * @param tokenPayload The NearAuthTokenPayload object.
 * @returns An object suitable for Borsh serialization.
 */
export function prepareNearAuthTokenPayloadForBorsh(
  tokenPayload: NearAuthTokenPayload,
): any {
  return {
    account_id: tokenPayload.account_id,
    public_key: tokenPayload.public_key,
    signature: tokenPayload.signature,
    signed_message_content: tokenPayload.signed_message_content,
    signed_nonce: tokenPayload.signed_nonce,
    signed_recipient: tokenPayload.signed_recipient,
    signed_callback_url: tokenPayload.signed_callback_url ?? null,
    state: tokenPayload.state ?? null,
    original_message_representation:
      tokenPayload.original_message_representation ?? null,
  };
}
