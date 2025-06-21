import { ed25519 } from "@noble/curves/ed25519";
import { base58, base64 } from "@scure/base";
import {
  ED25519_PREFIX,
  createNEP413Payload,
  hashPayload,
} from "../crypto/crypto.js";
import type { NonceType, SignOptions, SignedPayload, WalletInterface } from "../types.js";
import { ensureUint8Array, generateNonce } from "../utils/nonce.js";
import { createAuthToken } from "./createAuthToken.js";
import { NearAuthData } from "../schemas.js";

interface InternalSignParameters {
  message: string;
  recipient: string;
  nonce: Uint8Array; // Actual nonce bytes
  callbackUrl?: string | null;
  state?: string | null;
}

async function _signWithKeyPair(
  keyPair: string,
  signerId: string,
  params: InternalSignParameters,
): Promise<string> {
  const { message, recipient, nonce, callbackUrl } = params;

  const payload: SignedPayload = {
    message: message,
    nonce: Array.from(nonce),
    recipient: recipient,
    callbackUrl: callbackUrl || null,
  };

  const dataToHash = createNEP413Payload(payload);

  const payloadHash = hashPayload(dataToHash);

  if (!keyPair.startsWith(ED25519_PREFIX)) {
    throw new Error("Invalid KeyPair format: missing ed25519 prefix.");
  }
  const privateKeyBase58 = keyPair.substring(ED25519_PREFIX.length);
  const privateKeyBytes = base58.decode(privateKeyBase58);

  if (privateKeyBytes.length !== 64) {
    throw new Error(
      `Expected decoded private key to be 64 bytes for Ed25519, got ${privateKeyBytes.length}`,
    );
  }
  const seed = privateKeyBytes.slice(0, 32); // Extract the 32-byte seed

  const signedResult = ed25519.sign(payloadHash, seed);

  const actualSignatureB64 = base64.encode(signedResult);

  const publicKeyBytes = ed25519.getPublicKey(seed);
  const publicKeyString = ED25519_PREFIX + base58.encode(publicKeyBytes);

  const nearAuthDataObject: NearAuthData = {
    accountId: signerId,
    publicKey: publicKeyString,
    signature: actualSignatureB64,
    message: message,
    nonce: Array.from(nonce),
    recipient: recipient,
    callbackUrl: callbackUrl || null,
    state: params.state || null,
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
  // walletResult.state is optional and passed through if present

  const sigParts = walletResult.signature.split(":");
  if (sigParts.length !== 2 || sigParts[0].toLowerCase() !== "ed25519") {
    throw new Error(
      `Unsupported signature format from wallet: ${walletResult.signature}. Expected "ed25519:<base58_signature>"`,
    );
  }
  const base58EncodedSignature = sigParts[1];

  // Decode the Base58 signature to get the raw 64-byte signature
  const rawSignatureBytes = base58.decode(base58EncodedSignature);

  // Base64 encode the raw signature bytes
  const actualSignatureB64 = base64.encode(rawSignatureBytes);

  const nearAuthDataObject: NearAuthData = {
    accountId: walletResult.accountId,
    publicKey: walletResult.publicKey, // full "ed25519:<base58_pk>" string
    signature: actualSignatureB64, // Base64 of the *raw* 64-byte signature
    message: message,
    nonce: Array.from(nonce),
    recipient: recipient,
    callbackUrl: callbackUrl || null,
    state: walletResult.state || null,
  };

  return createAuthToken(nearAuthDataObject);
}

function detectSignerType(
  signer: string | WalletInterface,
): "keypair" | "wallet" {
  if (typeof (signer as WalletInterface).signMessage === "function") {
    return "wallet";
  }
  if (typeof signer === "string" && signer.startsWith(ED25519_PREFIX)) {
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
 * @param message The message to sign, can be application specific data.
 * @param options The signing options.
 * @returns A promise that resolves to the final AuthToken string.
 */
export async function sign<TNonce extends NonceType = Uint8Array>(
  message: string,
  options: SignOptions<TNonce>,
): Promise<string> {
  const { signer, accountId, recipient, callbackUrl, nonce, state } = options;

  const currentNonce = nonce || generateNonce();
  const nonceAsUint8Array = ensureUint8Array(currentNonce);

  const internalParams: InternalSignParameters = {
    message: message,
    recipient: recipient,
    nonce: nonceAsUint8Array,
    callbackUrl: callbackUrl || null,
    state: state || null,
  };

  const signerType = detectSignerType(signer);

  if (signerType === "keypair") {
    if (!accountId) {
      throw new Error("accountId is required when using a KeyPair signer.");
    }
    return _signWithKeyPair(signer as string, accountId, internalParams);
  }

  // For wallet, accountId comes from the wallet's response, not from options.
  return _signWithWallet(signer as WalletInterface, internalParams);
}
