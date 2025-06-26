export { NearAuthData, SignedPayload } from "./schemas.js";

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
   * Optional nonce. If not provided, a nonce will be generated.
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
  callbackUrl?: string;
}

/**
 * Options for validating the nonce in the `verify` function.
 */
type NonceValidationOptions =
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
    };

/**
 * Options for validating the recipient in the `verify` function.
 */
type RecipientValidationOptions =
  | {
      /**
       * The `recipient` field in the verified message must exactly match this string.
       * If not provided, any recipient will be valid.
       * This option is mutually exclusive with `validateRecipient`.
       */
      expectedRecipient?: string;
      validateRecipient?: never; // Ensures validateRecipient is not provided with expectedRecipient
    }
  | {
      /**
       * A custom function to validate the recipient.
       * Should return true if the recipient is valid, false otherwise.
       * This option is mutually exclusive with `expectedRecipient`.
       */
      validateRecipient: (recipient: string) => boolean;
      expectedRecipient?: never; // Ensures expectedRecipient is not provided with validateRecipient
    };

/**
 * Options for validating the state in the `verify` function.
 */
type StateValidationOptions =
  | {
      /**
       * The `state` field in the verified message must exactly match this string.
       * This option is mutually exclusive with `validateState`.
       */
      expectedState?: string;
      validateState?: never; // Ensures validateState is not provided with expectedState
    }
  | {
      /**
       * A custom function to validate the state.
       * Should return true if the state is valid, false otherwise.
       * This option is mutually exclusive with `expectedState`.
       */
      validateState: (state?: string) => boolean;
      expectedState?: never; // Ensures expectedState is not provided with validateState
    };

/**
 * Options for validating the message in the `verify` function.
 */
type MessageValidationOptions =
  | {
      /**
       * The `message` field in the verified token must exactly match this string.
       * This option is mutually exclusive with `validateMessage`.
       */
      expectedMessage?: string;
      validateMessage?: never; // Ensures validateMessage is not provided with expectedMessage
    }
  | {
      /**
       * A custom function to validate the message.
       * Should return true if the message is valid, false otherwise.
       * This option is mutually exclusive with `expectedMessage`.
       */
      validateMessage: (message: string) => boolean;
      expectedMessage?: never; // Ensures expectedMessage is not provided with validateMessage
    };

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
} & NonceValidationOptions &
  RecipientValidationOptions &
  StateValidationOptions &
  MessageValidationOptions;

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
  nonce: Uint8Array | Buffer; // A nonce that uniquely identifies this instance (32 bytes). (Buffer for near-wallet-selector)
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
