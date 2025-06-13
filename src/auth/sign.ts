import { fromBase58, toBase58 } from "@fastnear/utils";
import { ed25519 } from "@noble/curves/ed25519";
import { ED25519_PREFIX, TAG, hashForSigning } from "../crypto/crypto.js";
import type {
  SignOptions,
  WalletInterface,
  SignMessageParams,
  SignedPayload,
  NearAuthTokenPayload,
  SignedMessage,
} from "../types.js";
import { uint8ArrayToBase64 } from "../utils/encoding.js";
import { generateNonce } from "../utils/nonce.js";
import { createAuthToken } from "./createAuthToken.js";

// Helper to ensure nonce is Uint8Array
function normalizeNonce(nonceInput?: Uint8Array | number): Uint8Array {
  if (nonceInput instanceof Uint8Array) {
    if (nonceInput.length !== 32) {
      throw new Error(
        `Provided nonce Uint8Array must be 32 bytes, got ${nonceInput.length}`,
      );
    }
    return nonceInput;
  }
  if (typeof nonceInput === "number") {
    // If a number is provided, we could try to fit it into 32 bytes,
    // but NEP-413 implies a random or more robust nonce.
    // For now, let's rely on generateNonce() if a full Uint8Array isn't given,
    // or throw if a number is given without a clear conversion strategy.
    // Defaulting to generateNonce() if input is number might be unexpected.
    // For simplicity, this example will use generateNonce() if no Uint8Array is passed.
    // A more robust solution might involve specific conversion or clearer error handling.
    console.warn(
      "Numeric nonce provided; using generated nonce instead. For specific numeric nonces, provide as a 32-byte Uint8Array.",
    );
    return generateNonce();
  }
  return generateNonce(); // Default if undefined or unhandled type
}

// Helper to serialize message
function serializeMessage<TMessage>(
  message: TMessage,
  serializer?: (msg: TMessage) => string,
): string {
  if (typeof message === "string") {
    return message;
  }
  if (serializer) {
    return serializer(message);
  }
  try {
    return JSON.stringify(message);
  } catch (e) {
    throw new Error(
      "Failed to serialize message to string. Provide a custom messageSerializer or ensure message is stringifiable.",
    );
  }
}

async function _signWithKeyPair<TMessage>(
  keyPairString: string,
  signerId: string,
  options: SignOptions<TMessage>,
  serializedMessage: string,
  nonceBytes: Uint8Array,
): Promise<string> {
  const { recipient, callbackUrl, state } = options;

  const payload: SignedPayload = {
    message: serializedMessage,
    nonce: nonceBytes,
    recipient: recipient,
    callbackUrl: callbackUrl || undefined,
  };

  const payloadHash = hashForSigning(TAG, payload);

  if (!keyPairString.startsWith(ED25519_PREFIX)) {
    throw new Error("Invalid KeyPair format: missing ed25519 prefix.");
  }
  const privateKeyBase58 = keyPairString.substring(ED25519_PREFIX.length);
  const privateKeyBytes = fromBase58(privateKeyBase58);

  // Assuming privateKeyBytes from fromBase58 for ed25519 is the 32-byte seed or 64-byte seed+pubkey
  // noble/ed25519 sign function expects a 32-byte private key (seed)
  let seed: Uint8Array;
  if (privateKeyBytes.length === 64) {
    seed = privateKeyBytes.slice(0, 32); // Extract the 32-byte seed
  } else if (privateKeyBytes.length === 32) {
    seed = privateKeyBytes;
  } else {
    throw new Error(
      `Expected decoded private key (seed) to be 32 or 64 bytes for Ed25519, got ${privateKeyBytes.length}`,
    );
  }

  const rawSignature = ed25519.sign(payloadHash, seed);
  const signatureB64 = uint8ArrayToBase64(rawSignature);
  const publicKeyBytes = ed25519.getPublicKey(seed);
  const publicKeyString = ED25519_PREFIX + toBase58(publicKeyBytes);

  const tokenPayload: NearAuthTokenPayload = {
    account_id: signerId,
    public_key: publicKeyString,
    signature: signatureB64,
    signed_message_content: serializedMessage,
    signed_nonce: nonceBytes,
    signed_recipient: recipient,
    signed_callback_url: callbackUrl || undefined,
    state: state || undefined,
    original_message_representation:
      typeof options.message === "string" ? undefined : serializedMessage,
  };

  return createAuthToken(tokenPayload);
}

async function _signWithWallet<TMessage>(
  wallet: WalletInterface,
  options: SignOptions<TMessage>,
  serializedMessage: string,
  nonceBytes: Uint8Array,
): Promise<string> {
  const { recipient, callbackUrl, state } = options;

  const nepSignParams: SignMessageParams = {
    message: serializedMessage,
    recipient: recipient,
    nonce: nonceBytes,
    callbackUrl: callbackUrl || undefined,
    state: state || undefined,
  };

  const walletSignedMessage: SignedMessage =
    await wallet.signMessage(nepSignParams);

  // Wallet is expected to return signature as base64 of raw signature per NEP-413 SignedMessage.
  // If it returns "ed25519:<bs58_sig>", we'd need to convert it.
  // For now, assume it's already base64 of raw.
  // If not, the following logic would be needed:
  // let signatureB64 = walletSignedMessage.signature;
  // if (walletSignedMessage.signature.includes(':')) {
  //   const sigParts = walletSignedMessage.signature.split(":");
  //   if (sigParts.length === 2 && sigParts[0].toLowerCase() === "ed25519") {
  //     const rawSignatureBytes = fromBase58(sigParts[1]);
  //     signatureB64 = uint8ArrayToBase64(rawSignatureBytes);
  //   } else {
  //     throw new Error(`Unsupported signature format from wallet: ${walletSignedMessage.signature}`);
  //   }
  // }


  const tokenPayload: NearAuthTokenPayload = {
    account_id: walletSignedMessage.accountId,
    public_key: walletSignedMessage.publicKey,
    signature: walletSignedMessage.signature, // Assumed to be Base64 of raw signature
    signed_message_content: serializedMessage,
    signed_nonce: nonceBytes,
    signed_recipient: recipient,
    signed_callback_url: callbackUrl || undefined,
    state: walletSignedMessage.state || state || undefined, // Prioritize state from wallet response if present
    original_message_representation:
      typeof options.message === "string" ? undefined : serializedMessage,
  };

  return createAuthToken(tokenPayload);
}

function detectSignerType(
  signer: string | WalletInterface,
): "keypair" | "wallet" {
  if (
    typeof signer === "object" &&
    signer !== null &&
    typeof (signer as WalletInterface).signMessage === "function"
  ) {
    return "wallet";
  }
  if (typeof signer === "string" && signer.startsWith(ED25519_PREFIX)) {
    return "keypair";
  }
  throw new Error(
    "Invalid signer: must be a KeyPair string (e.g., 'ed25519:...') or a wallet object implementing WalletInterface.",
  );
}

/**
 * Signs a message using either a KeyPair or a wallet, creating a NEAR authentication token
 * compliant with aspects of NEP-413.
 *
 * @param options The signing options, including the message (can be generic type TMessage).
 * @returns A promise that resolves to the final AuthToken string.
 */
export async function sign<TMessage = string>(
  options: SignOptions<TMessage>,
): Promise<string> {
  const { signer, accountId, message, messageSerializer, nonce } = options;

  const currentNonceBytes = normalizeNonce(nonce);
  const serializedMessageForSigning = serializeMessage(
    message,
    messageSerializer,
  );

  const signerType = detectSignerType(signer);

  if (signerType === "keypair") {
    if (!accountId) {
      throw new Error("accountId is required when using a KeyPair signer.");
    }
    return _signWithKeyPair(
      signer as string,
      accountId,
      options,
      serializedMessageForSigning,
      currentNonceBytes,
    );
  } else {
    // WalletInterface
    return _signWithWallet(
      signer as WalletInterface,
      options,
      serializedMessageForSigning,
      currentNonceBytes,
    );
  }
}
