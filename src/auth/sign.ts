import { fromBase58 } from "@fastnear/utils";
import { ed25519 } from "@noble/curves/ed25519";
import {
  ED25519_PREFIX,
  hashPayload,
  serializePayload,
  TAG,
} from "../crypto/crypto.js";
import type {
  NearAuthData,
  NearAuthPayload,
  SignOptions,
  WalletInterface,
} from "../types.js";
import { uint8ArrayToBase64 } from "../utils/encoding.js";
import { generateNonce } from "../utils/nonce.js";
import { createAuthToken } from "./createAuthToken.js";

interface InternalSignParameters {
  message: string;
  recipient: string;
  nonce: Uint8Array; // Actual nonce bytes
  callbackUrl?: string | null;
}

async function _signWithKeyPair(
  keyPair: string,
  signerId: string,
  params: InternalSignParameters,
): Promise<string> {
  const { message, recipient, nonce, callbackUrl } = params;

  const payloadToSerialize: NearAuthPayload = {
    tag: TAG,
    message: message,
    nonce,
    receiver: recipient,
    callback_url: callbackUrl || undefined,
  };

  const serializedPayload = serializePayload(payloadToSerialize);
  const payloadHash = hashPayload(serializedPayload);

  const signedResult = ed25519.sign(payloadHash, fromBase58(keyPair));

  const actualSignatureB64 = uint8ArrayToBase64(signedResult);

  const nearAuthDataObject: NearAuthData = {
    account_id: signerId,
    public_key: ed25519.getPublicKey(fromBase58(keyPair)).toString(),
    signature: actualSignatureB64,
    message: message,
    // @ts-expect-error Type 'Uint8Array<ArrayBufferLike>' is not assignable to type 'Uint8Array<ArrayBuffer>'
    nonce: nonce,
    recipient: recipient,
    callback_url: callbackUrl || null,
  };

  return createAuthToken(nearAuthDataObject);
}

async function _signWithWallet(
  wallet: WalletInterface,
  params: InternalSignParameters,
): Promise<string> {
  const { message, recipient, nonce, callbackUrl } = params;

  const walletResult = await wallet.signMessage({
    message,
    nonce,
    recipient,
  });
  // walletResult.signature is expected to be a string like "ed25519:Base58EncodedSignature"
  // walletResult.publicKey is expected to be a string like "ed25519:Base58EncodedPublicKey"

  const sigParts = walletResult.signature.split(":");
  if (sigParts.length !== 2 || sigParts[0].toLowerCase() !== "ed25519") {
    throw new Error(
      `Unsupported signature format from wallet: ${walletResult.signature}. Expected "ed25519:<base58_signature>"`,
    );
  }
  const base58EncodedSignature = sigParts[1];

  // Decode the Base58 signature to get the raw 64-byte signature
  const rawSignatureBytes = fromBase58(base58EncodedSignature);

  // Base64 encode the raw signature bytes
  const actualSignatureB64 = uint8ArrayToBase64(rawSignatureBytes);

  const nearAuthDataObject: NearAuthData = {
    account_id: walletResult.accountId,
    public_key: walletResult.publicKey, // full "ed25519:<base58_pk>" string
    signature: actualSignatureB64, // Base64 of the *raw* 64-byte signature
    message: message, // JSON string from createMessage
    // @ts-expect-error Type 'Uint8Array<ArrayBufferLike>' is not assignable to type 'Uint8Array<ArrayBuffer>'
    nonce: nonce, // actualNonceBytes (Uint8Array)
    recipient: recipient,
    callback_url: callbackUrl || null,
  };

  return createAuthToken(nearAuthDataObject);
}

function detectSignerType(
  signer: string | WalletInterface,
): "keypair" | "wallet" {
  if (typeof (signer as WalletInterface).signMessage === "function") {
    return "wallet";
  }
  if ((signer as string).startsWith(ED25519_PREFIX)) {
    return "keypair";
  }
  throw new Error(
    "Invalid signer: must be KeyPair or a wallet object with a signMessage method.",
  );
}

/**
 * Signs a message using either a KeyPair or a wallet, creating a structured
 * message and producing a NEAR authentication token.
 *
 * @param options The signing options.
 * @returns A promise that resolves to the final AuthToken string.
 */
export async function sign(options: SignOptions): Promise<string> {
  const { signer, accountId, recipient, message, callbackUrl, nonce } = options;

  const currentNonce = nonce || generateNonce();

  const internalParams: InternalSignParameters = {
    message,
    recipient: recipient,
    nonce: currentNonce,
    callbackUrl: callbackUrl,
  };

  const signerType = detectSignerType(signer);

  if (signerType === "keypair") {
    if (!accountId) {
      throw new Error("accountId is required when using a KeyPair signer.");
    }
    return _signWithKeyPair(signer as string, accountId, internalParams);
  } else {
    // For wallet, accountId comes from the wallet's response, not from options.
    return _signWithWallet(signer as WalletInterface, internalParams);
  }
}
