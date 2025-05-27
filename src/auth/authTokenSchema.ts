import type { NearAuthData } from "../types.js";

/**
 * Borsh schema for NearAuthData
 */
export const nearAuthDataBorshSchema = {
  struct: {
    account_id: "string",
    public_key: "string",
    signature: "string",
    message: "string",
    nonce: { array: { type: "u8", len: 32 } },
    recipient: "string",
    callback_url: { option: "string" },
  },
};

/**
 * Helper function to prepare data for Borsh serialization
 * (handling optional fields properly)
 */
export function prepareBorshData(authData: NearAuthData): any {
  return {
    account_id: authData.account_id,
    public_key: authData.public_key,
    signature: authData.signature,
    message: authData.message,
    nonce: authData.nonce,
    recipient: authData.recipient,
    callback_url: authData.callback_url || null,
  };
}
