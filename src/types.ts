/**
 * Types for NEAR Simple Signing
 */

/**
 * NEAR Authentication Data
 */
export interface NearAuthData {
  /**
   * NEAR account ID
   */
  account_id: string;

  /**
   * Public key used for signing
   */
  public_key: string;

  /**
   * Signature of the message
   */
  signature: string;

  /**
   * Message that was signed
   */
  message: string;

  /**
   * Nonce used for signing
   */
  nonce: string;

  /**
   * Recipient of the message
   */
  recipient?: string;

  /**
   * Callback URL
   */
  callback_url?: string;
}

/**
 * NEAR Authentication Payload
 */
export interface NearAuthPayload {
  /**
   * Tag value for the payload (2147484061)
   */
  tag: number;

  /**
   * Message that was signed
   */
  message: string;

  /**
   * Nonce used for signing
   */
  nonce: Uint8Array;

  /**
   * Recipient of the message
   */
  receiver: string;

  /**
   * Callback URL
   */
  callback_url?: string;
}

/**
 * Signature validation parameters
 */
export interface ValidateSignatureParams {
  /**
   * Signature to validate
   */
  signature: string;

  /**
   * Message that was signed
   */
  message: string;

  /**
   * Public key to validate against
   */
  publicKey: string;

  /**
   * Nonce used for signing
   */
  nonce: string;

  /**
   * Recipient of the message
   */
  recipient: string;
}

/**
 * Validation result
 */
export interface ValidationResult {
  /**
   * Whether the signature is valid
   */
  valid: boolean;

  /**
   * Error message if invalid
   */
  error?: string;
}
