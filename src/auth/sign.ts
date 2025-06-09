import { fromBase58 } from "@fastnear/utils";
import { ed25519 } from "@noble/curves/ed25519";
import { ED25519_PREFIX, hashPayload, serializePayload, TAG } from "../crypto/crypto.js";
import type {
  NearAuthData,
  NearAuthPayload,
  SignOptions,
  WalletInterface,
} from "../types.js";
import { createMessage } from "../utils/createMessage.js";
import { uint8ArrayToBase64 } from "../utils/encoding.js";
import { createAuthToken } from "./createAuthToken.js";

interface InternalSignParameters {
  message: string; // JSON string from createMessage
  recipient: string;
  nonce: Uint8Array; // Actual nonce bytes from createMessage
  callbackUrl?: string | null;
}

async function _signWithKeyPair(
  keyPair: string,
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
  params: InternalSignParameters
): Promise<string> {
  const { message, recipient, nonce, callbackUrl } = params;

  const walletResult = await wallet.signMessage({
    message,
    nonce,
    recipient
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
  signer: string | WalletInterface
): "keypair" | "wallet" {
  if (typeof (signer as WalletInterface).signMessage === "function") {
    return "wallet";
  }
  if (  
    (signer as string).startsWith(ED25519_PREFIX)
  ) {
    return "keypair";
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
    return _signWithKeyPair(signer as string, accountId, internalParams);
  } else {
    // For wallet, accountId comes from the wallet's response, not from options.
    return _signWithWallet(signer as WalletInterface, internalParams);
  }
}
