import { z } from "zod";

/**
 * Type for raw deserialized Borsh data
 */
export interface BorshNearAuthData {
  account_id: string;
  public_key: string;
  signature: string;
  message: string;
  nonce: number[];
  recipient: string;
  callback_url: string | null;
  state: string | null;
}

export const NearAuthDataSchema = z.object({
  /**
   * NEAR account ID
   */
  account_id: z.string(),

  /**
   * Public key used for signing
   */
  public_key: z.string(),

  /**
   * Signature of the message
   */
  signature: z.string(),

  /**
   * Message that was signed
   */
  message: z.string(),

  /**
   * Nonce used for signing
   */
  nonce: z.union([
    z.instanceof(Uint8Array),
    z.array(z.number()).transform((arr) => new Uint8Array(arr)),
  ]),

  /**
   * Recipient of the message
   */
  recipient: z.string(),

  /**
   * Callback URL (for usage by backend)
   */
  callback_url: z.string().nullable().optional(),

  /**
   * Optional state parameter (comes from signature, might be useful)
   */
  state: z.string().nullable().optional(),
});

/**
 * NEAR Authentication Data
 */
export type NearAuthData = z.infer<typeof NearAuthDataSchema>;

/**
 * NEAR Authentication Payload Schema
 */
export const NearAuthPayloadSchema = z.object({
  /**
   * Tag value for the payload (2147484061)
   */
  tag: z.number(),

  /**
   * Message that was signed
   */
  message: z.string(),

  /**
   * Nonce used for signing
   */
  nonce: z.instanceof(Uint8Array),

  /**
   * Recipient of the message
   */
  receiver: z.string(),

  /**
   * Callback URL (for usage by backend)
   */
  callback_url: z.string().optional(),

  /**
   * Optional state parameter (comes from signature, might be useful)
   */
  state: z.string().optional(),
});

/**
 * NEAR Authentication Payload
 */
export type NearAuthPayload = z.infer<typeof NearAuthPayloadSchema>;

/**
 * Validation result schema
 */
export const ValidationResultSchema = z.object({
  /**
   * Whether the signature is valid
   */
  valid: z.boolean(),

  /**
   * Error message if invalid
   */
  error: z.string().optional(),
});

/**
 * Validation result
 */
export type ValidationResult = z.infer<typeof ValidationResultSchema>;
