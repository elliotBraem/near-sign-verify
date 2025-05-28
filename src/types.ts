import { z } from "zod";
import type { KeyPair } from "@near-js/crypto";

// --- Core Data Structures ---

/**
 * Represents the structured data within the message string that is signed.
 */
export interface MessageData {
  nonce: string; // Base64 encoded nonce
  timestamp: number; // Unix timestamp (milliseconds)
  recipient: string; // Intended recipient of the message/action
  data?: string | Record<string, any>; // Optional application-specific data
}

/**
 * Options for the main `sign` function.
 */
export interface SignOptions {
  /**
   * The signer, which can be a NEAR KeyPair or a wallet object.
   * The library will detect the type at runtime.
   */
  signer: KeyPair | WalletInterface;
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
   * Optional application-specific data to include in the message.
   * Can be a string or a JSON-serializable object.
   */
  data?: string | Record<string, any>;
  /**
   * Optional 32-byte nonce as a Uint8Array.
   * If not provided, a nonce will be generated.
   */
  nonce?: Uint8Array;
  /**
   * Optional callback URL string.
   * If provided, it will be included in the signed payload.
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
   */
  requireFullAccessKey?: boolean;
  /**
   * If provided, the `recipient` field in the verified message
   * must exactly match this string.
   */
  expectedRecipient?: string;
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
       * Receives the parsed `MessageData` object.
       * Should return true if the nonce is valid, false otherwise.
       * This option is mutually exclusive with `nonceMaxAge`.
       */
      validateNonce: (messageData: MessageData) => boolean;
      nonceMaxAge?: never; // Ensures nonceMaxAge is not provided with validateNonce
    }
);

/**
 * The result of a successful verification.
 */
export interface VerificationResult {
  /** The NEAR account ID that was successfully authenticated. */
  accountId: string;
  /** The parsed MessageData object from the verified token. */
  messageData: MessageData;
  /** The public key string used for the signature. */
  publicKey: string;
  /** The callback URL from the token, if present. */
  callbackUrl?: string | null;
}

/**
 * Defines the interface for a wallet signer.
 * This allows for duck-typing of wallet objects.
 */
export interface WalletInterface {
  signMessage: (
    // Wallets typically sign a message (often a string or Uint8Array representing a hash or pre-image)
    // The `sign` function will prepare the canonical NearAuthPayload, hash it,
    // and then the wallet's signMessage would sign that hash.
    // However, to keep this interface generic to how wallets actually behave,
    // we expect the wallet's signMessage to handle the hashing if it needs to.
    // The `sign` function will pass the *pre-hashed* canonical payload to this.
    // This needs careful implementation in the `sign` function.
    // For now, let's assume the wallet expects the message it needs to sign directly.
    // The `sign` function will construct the NearAuthPayload, serialize it, and pass it here.
    // The wallet is then responsible for hashing (if necessary) and signing.
    messageToSign: {
      message: Uint8Array; // The canonical bytes to be signed (or hashed then signed)
      // Some wallets might need more context, but this is the core.
      // We might need to adjust this if wallets require the pre-image of a hash.
      // For now, this is the serialized NearAuthPayload.
    }
  ) => Promise<{
    signature: Uint8Array; // Raw signature bytes
    publicKey: string; // Public key string of the signing key
    accountId: string; // Account ID that performed the signature
  }>;
}

// --- Existing Internal Types (may need review/adjustment) ---

/**
 * Type for raw deserialized Borsh data from the auth token.
 * This is what `parseAuthToken` initially deserializes to.
 */
export interface BorshNearAuthData {
  account_id: string;
  public_key: string;
  signature: string; // Base64 encoded signature of the hashed NearAuthPayload
  message: string; // The JSON.stringified MessageData object
  nonce: number[]; // Borsh representation of Uint8Array
  recipient: string; // Recipient from the SignOptions, part of NearAuthPayload
  callback_url: string | null;
}

/**
 * Zod schema for validating and transforming BorshNearAuthData.
 * This is used by `parseAuthToken`.
 */
export const NearAuthDataSchema = z.object({
  account_id: z.string(),
  public_key: z.string(),
  signature: z.string(),
  message: z.string(), // This will be the JSON string of MessageData
  nonce: z.union([ // Nonce from the NearAuthPayload
    z.instanceof(Uint8Array),
    z.array(z.number()).transform((arr) => new Uint8Array(arr)),
  ]),
  recipient: z.string(), // Recipient from the NearAuthPayload
  callback_url: z.string().nullable().optional(),
});

/**
 * Represents the fully parsed and validated data from an auth token.
 * This is the output type of `parseAuthToken`.
 */
export type NearAuthData = z.infer<typeof NearAuthDataSchema>;

/**
 * Represents the canonical payload that is Borsh-serialized, hashed, and then signed.
 * This structure is internal to the signing and verification process.
 */
export interface NearAuthPayload {
  tag: number; // A constant tag (e.g., 2147484061 from crypto.ts)
  message: string; // The JSON.stringified MessageData object
  nonce: Uint8Array; // The actual nonce bytes
  receiver: string; // The recipient
  callback_url?: string; // Optional callback URL
}

// Zod schema for NearAuthPayload might be useful for internal validation if needed,
// but it's primarily an interface for structuring data before Borsh serialization.
// For now, an interface is sufficient.

// Old ValidationResult type - replaced by VerificationResult or throwing errors.
// export const ValidationResultSchema = z.object({
//   valid: z.boolean(),
//   error: z.string().optional(),
// });
// export type ValidationResult = z.infer<typeof ValidationResultSchema>;
