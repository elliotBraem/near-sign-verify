export { NearAuthPayload, NearAuthData } from "./schemas.js";

/**
 * Options for the main `sign` function.
 */
export interface SignOptions {
  /**
   * The signer, which can be a NEAR KeyPair or a wallet object.
   * The library will detect the type at runtime.
   */
  signer: string | WalletInterface;
  /**
   * The NEAR account ID of the intended signer.
   * Required if `signer` is a KeyPair. Ignored if `signer` is a wallet
   * (as the wallet will provide the accountId).
   */
  accountId?: string;
  /**
   * The intended recipient of the signed message or action.
   * This will be included in the structured message and the signed payload.
   */
  recipient: string;
  /**
   * Optional 32-byte nonce as a Uint8Array.
   * If not provided, a nonce will be generated.
   */
  nonce?: Uint8Array;
  /**
   * Optional state object for authentication purposes, to be verified on backend.
   * This is recommended to help mitigate CSRF attacks.
   */
  state?: string;
  /**
   * Optional callback URL string.
   * If provided, this URL will receive a call after the signing process with the accountId, publicKey, signature, and state
   * <callbackUrl>#accountId=<accountId>&publicKey=<publicKey>&signature=<signature>&state=<state>.
   */
  callbackUrl?: string | null;
}

/**
 * Options for the main `verify` function.
 */
export type VerifyOptions = {
  /**
   * Whether the public key used for signing must be a Full Access Key.
   * Defaults to true. If false, Function Call Access Keys are permitted
   * provided they have permission for the `recipient`.
   * 
   * Full access is highly recommended, otherwise ensure message, nonce, and state validation are enforced.
   */
  requireFullAccessKey?: boolean;
} & (
    | {
      /**
       * Maximum age of the nonce in milliseconds.
       * If not provided, a default value (e.g., 24 hours) will be used.
       * This option is mutually exclusive with `validateNonce`.
       */
      nonceMaxAge?: number;
      validateNonce?: never; // Ensures validateNonce is not provided with nonceMaxAge
    }
    | {
      /**
       * A custom function to validate the nonce.
       * Should return true if the nonce is valid, false otherwise.
       * This option is mutually exclusive with `nonceMaxAge`.
       */
      validateNonce: (nonce: Uint8Array) => boolean;
      nonceMaxAge?: never; // Ensures nonceMaxAge is not provided with validateNonce
    }
    & (
      | {
        /**
         * The `recipient` field in the verified message must exactly match this string.
         * If not provided, any recipient will be valid.
         * This option is mutually exclusive with `validateRecipient`
         */
        expectedRecipient?: string;
        validateRecipient?: never; // Ensures validateRecipient is not provided with expectedRecipient
      }
      | {
        /**
         * A custom function to validate the recipient.
         * Should return false if the recipient is valid, false otherwise.
         * This option is mutually exclusive with `expectedRecipient`;
         */
        validateRecipient?: (recipient: string) => boolean;
        expectedRecipient?: never; // Ensures expectedRecipient is not provided with validateRecipient
      }
    )
  );

// expectedState?: string; // For simple state equality check.
// validateState?: (state?: string) => boolean; // For custom state validation.

/**
 * The result of a successful verification.
 */
export interface VerificationResult {
  /** The NEAR account ID that was successfully authenticated. */
  accountId: string;
  /** The parsed message from the verified token. */
  message: string;
  /** The public key string used for the signature. */
  publicKey: string;
  /** The callback URL from the token, if present. */
  callbackUrl?: string;
  /** The state from the token, if present. */
  state?: string;
}

/** NEP-413: Parameters for the wallet's signMessage method. */
export interface SignMessageParams {
  message: string; // The message that wants to be transmitted (must be string for NEP-413 payload).
  recipient: string; // The recipient to whom the message is destined.
  nonce: Uint8Array; // A nonce that uniquely identifies this instance (32 bytes).
  callbackUrl?: string; // Optional URL to call after signing.
  state?: string; // Optional state for authentication purposes.
}

/** NEP-413: Output from the wallet's signMessage method. */
export interface SignedMessage {
  accountId: string; // The account name to which the publicKey corresponds as plain text (e.g. "alice.near")
  publicKey: string; // Public key used for signing ("ed25519:<bs58>").
  signature: string; // Base64 representation of the raw Ed25519 signature.
  state?: string; // Optional state passed through, from SignMessageParams.
}

// Wallet Interface (works for fastnear or near-wallet-selector)
export interface WalletInterface {
  /** Must conform to NEP-413 signMessage specification. */
  signMessage: (params: SignMessageParams) => Promise<SignedMessage>;
}


/** NEP-413: The structure whose Borsh representation (prepended with TAG) is hashed and signed. */
export interface SignedPayload {
  message: string; // Serialized version of the user's original message.
  nonce: Uint8Array;
  recipient: string;
  callbackUrl?: string;
}




/** Data structure encoded within the library's authTokenString. */
export interface NearAuthTokenPayload {
  account_id: string;
  public_key: string;
  signature: string; // Base64 of raw signature

  // Fields that were part of the signed SignedPayload
  signed_message_content: string; // This is SignedPayload.message
  signed_nonce: Uint8Array;       // This is SignedPayload.nonce
  signed_recipient: string;     // This is SignedPayload.recipient
  signed_callback_url?: string;  // This is SignedPayload.callbackUrl

  // Additional metadata for the token (not part of the signature hash)
  state?: string | null;
  // To reconstruct the original TMessage if it was not a simple string.
  original_message_representation?: string;
}
