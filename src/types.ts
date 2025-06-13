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
  accountId: string; // Account ID that signed.
  publicKey: string; // Public key used for signing ("ed25519:<bs58>").
  signature: string; // Base64 representation of the raw Ed25519 signature.
  state?: string; // Optional state passed through.
}

/** NEP-413: The structure whose Borsh representation (prepended with TAG) is hashed and signed. */
export interface SignedPayload {
  message: string; // Serialized version of the user's original message.
  nonce: Uint8Array;
  recipient: string;
  callbackUrl?: string;
}

// --- New types for the refactored sign function ---

/** Input payload for the sign function, containing the core data to be signed. */
export interface SignerMessagePayload<TMessage = string> {
  message: TMessage; // User's original message (can be structured).
  recipient: string; // The recipient to whom the message is destined.
}

/** Options for the sign function, specifying the signer and other signing parameters. */
export interface SignerOptions {
  signer: string | WalletInterface; // KeyPair string or a NEP-413 compliant wallet.
  accountId?: string; // Required if signer is KeyPair.
  nonce?: Uint8Array | number; // Library can convert number to a default nonce format if needed.
  state?: string; // Passed through, not part of SignedPayload for hashing, but included in SignMessageParams for wallet.
  callbackUrl?: string | null;
  /** Custom serializer for TMessage to string. Defaults to JSON.stringify if TMessage is not a string. */
  messageSerializer?: (message: any) => string; // 'any' because TMessage is on SignerMessagePayload
}
// --- End of new types for sign function ---


// Library's public API types (VerifyOptions and VerificationResult remain largely the same)
export interface VerifyOptions<TMessage = any> {
  expectedRecipient?: string;
  validateRecipient?: (recipient: string) => boolean;
  requireFullAccessKey?: boolean; // Defaults to true.
  nonceMaxAge?: number; // For default time-based nonce validation.
  validateNonce?: (nonce: Uint8Array) => boolean; // For custom nonce validation.
  expectedState?: string; // For simple state equality check.
  validateState?: (state?: string) => boolean; // For custom state validation.
  /** Custom parser for the 'original_message_string' from the token. Defaults to JSON.parse. */
  messageParser?: (messageString: string) => TMessage;
}

export interface VerificationResult<TMessage = any> {
  accountId: string;
  publicKey: string;
  message: TMessage; // The original, potentially structured, message.
  callbackUrl?: string;
  state?: string;
}

// Wallet Interface
export interface WalletInterface {
  /** Must conform to NEP-413 signMessage specification. */
  signMessage: (params: SignMessageParams) => Promise<SignedMessage>;
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

// --- Deprecated SignOptions from previous structure ---
// This is now replaced by SignerMessagePayload and SignerOptions
// export interface OldSignOptions<TMessage = string> {
//   signer: string | WalletInterface;
//   accountId?: string;
//   recipient: string;
//   message: TMessage;
//   callbackUrl?: string | null;
//   nonce?: Uint8Array | number;
//   state?: string;
//   messageSerializer?: (message: TMessage) => string;
// }
