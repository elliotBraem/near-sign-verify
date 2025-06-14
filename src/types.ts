import { z } from "zod";
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

// Old ValidationResult type - replaced by VerificationResult or throwing errors.
// export const ValidationResultSchema = z.object({
//   valid: z.boolean(),
//   error: z.string().optional(),
// });
// export type ValidationResult = z.infer<typeof ValidationResultSchema>;
