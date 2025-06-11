import { z } from "zod";

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
   * Message to sign, can be application specific data.
   */
  message: string;
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
       * Should return true if the nonce is valid, false otherwise.
       * This option is mutually exclusive with `nonceMaxAge`.
       */
      validateNonce: (nonce: Uint8Array) => boolean;
      nonceMaxAge?: never; // Ensures nonceMaxAge is not provided with validateNonce
    }
);

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
  callbackUrl?: string | null;
}

/**
 * Defines the interface for a wallet signer.
 * This allows for duck-typing of wallet objects.
 */
export interface WalletInterface {
  signMessage: (messageToSign: {
    message: string;
    recipient: string;
    nonce: Uint8Array<ArrayBufferLike>;
  }) => Promise<{
    signature: string;
    publicKey: string;
    accountId: string;
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
  message: string;
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
  message: z.string(),
  nonce: z.union([
    // Nonce from the NearAuthPayload
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
  message: string;
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
