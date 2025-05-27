import * as near from "near-api-js";
import type {
  SignOptions,
  NearAuthPayload,
  NearAuthData,
  WalletInterface,
} from "../types.js";
import { uint8ArrayToBase64 } from "../utils/encoding.js";
import { createMessage } from "../utils/createMessage.js";
import { hashPayload, serializePayload, TAG } from "../crypto/crypto.js";
import { createAuthToken } from "./createAuthToken.js";

interface InternalSignParameters {
  message: string; // JSON string from createMessage
  recipient: string;
  nonce: Uint8Array; // Actual nonce bytes from createMessage
  callbackUrl?: string | null;
}

async function _signWithKeyPair(
  keyPair: near.KeyPair,
  signerId: string,
  params: InternalSignParameters
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

  const signedResult = keyPair.sign(payloadHash);
  const actualSignatureB64 = uint8ArrayToBase64(signedResult.signature);

  const nearAuthDataObject: NearAuthData = {
    account_id: signerId,
    public_key: keyPair.getPublicKey().toString(),
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
  params: InternalSignParameters
): Promise<string> {
  const { message, recipient, nonce, callbackUrl } = params;

  const payloadToSerialize: NearAuthPayload = {
    tag: TAG,
    message: message,
    nonce: nonce,
    receiver: recipient,
    callback_url: callbackUrl || undefined,
  };

  const serializedPayload = serializePayload(payloadToSerialize);
  // Wallets are expected to sign the hash of the message, or the message itself if they handle hashing.
  // For consistency with KeyPair signing (which signs a hash), we should ideally pass the hash.
  // However, the WalletInterface is generic. Let's assume the wallet expects the raw bytes to sign/hash-and-sign.
  // The current WalletInterface expects `messageToSign: { message: Uint8Array }`
  // This `Uint8Array` should be the `serializedPayload` itself, not its hash,
  // as some wallets might want to display the pre-image or handle hashing differently.
  // If a wallet strictly needs a pre-computed hash, the interface might need adjustment or the wallet adapter.

  const walletResult = await wallet.signMessage({
    message: serializedPayload, // Pass the serialized payload for the wallet to handle
  });

  const actualSignatureB64 = uint8ArrayToBase64(walletResult.signature);

  const nearAuthDataObject: NearAuthData = {
    account_id: walletResult.accountId,
    public_key: walletResult.publicKey,
    signature: actualSignatureB64,
    message: message,
    // @ts-expect-error Type 'Uint8Array<ArrayBufferLike>' is not assignable to type 'Uint8Array<ArrayBuffer>'
    nonce,
    recipient: recipient,
    callback_url: callbackUrl || null,
  };

  return createAuthToken(nearAuthDataObject);
}

function detectSignerType(
  signer: near.KeyPair | WalletInterface
): "keypair" | "wallet" {
  if (
    typeof (signer as near.KeyPair).sign === "function" &&
    typeof (signer as near.KeyPair).getPublicKey === "function"
  ) {
    return "keypair";
  }
  if (typeof (signer as WalletInterface).signMessage === "function") {
    return "wallet";
  }
  throw new Error(
    "Invalid signer: must be KeyPair or a wallet object with a signMessage method."
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
  const { signer, accountId, recipient, data, callbackUrl } = options;

  // Use the new createMessage helper
  const { message: structuredMessageString, nonce: actualNonceBytes } =
    createMessage({
      recipient: recipient,
      nonce: options.nonce, // Pass through user-provided nonce if any
      data: data,
    });

  const internalParams: InternalSignParameters = {
    message: structuredMessageString,
    recipient: recipient,
    nonce: actualNonceBytes,
    callbackUrl: callbackUrl,
  };

  const signerType = detectSignerType(signer);

  if (signerType === "keypair") {
    if (!accountId) {
      throw new Error("accountId is required when using a KeyPair signer.");
    }
    return _signWithKeyPair(signer as near.KeyPair, accountId, internalParams);
  } else {
    // For wallet, accountId comes from the wallet's response, not from options.
    return _signWithWallet(signer as WalletInterface, internalParams);
  }
}
