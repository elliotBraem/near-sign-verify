import { z } from "zod";

/**
 * NEAR Authentication Data Schema
 */
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
  nonce: z.string(),

  /**
   * Recipient of the message
   */
  recipient: z.string(),

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
 * NEAR Authentication Data
 */
export type NearAuthData = z.infer<typeof NearAuthDataSchema>;

/**
 * NEAR Authentication Payload Schema
 */
export const NearAuthPayloadSchema = z.object({
  /**
   * Tag value for the payload (2147484061), idk what this means yet, it's straight from nearai
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
