import dotenv from "dotenv";
import * as near from "near-api-js";
import { KeyPairString } from "near-api-js/lib/utils/key_pair.js";
import { beforeAll, describe, expect, it } from "vitest";
import {
  generateNonce,
  NearAuthData,
  parseAuthToken,
  sign,
  SignOptions,
  verify,
  createMessage,
  VerificationResult
} from "../../src/index.js";
import { uint8ArrayToBase64 } from "../../src/utils/encoding.js";

dotenv.config();

const ACCOUNT_ID = "signverifytests.testnet";
const FCAK_PUBLIC_KEY_STR = "ed25519:DKFEx1W5rxMNVAnqJ25Cq47Xvys4zZsrJg8bzgT971vt";
let FCAK_KEY_PAIR: near.KeyPair;

describe("Sign Function", () => {
  beforeAll(() => {
    const fcakSecretKey = process.env.FCAK_SECRET_KEY!;
    if (!fcakSecretKey) {
      throw new Error(
        "FCAK_SECRET_KEY not found in environment variables. Please ensure .env file is set up correctly."
      );
    }
    FCAK_KEY_PAIR = near.KeyPair.fromString(fcakSecretKey as KeyPairString);
    if (FCAK_KEY_PAIR.getPublicKey().toString() !== FCAK_PUBLIC_KEY_STR) {
      throw new Error(
        "Provided FCAK_SECRET_KEY does not match FCAK_PUBLIC_KEY_STR."
      );
    }
  });

  it("should sign a message with KeyPair and produce a verifiable auth token", async () => {
    const appData = { info: "Test message for signing" };
    const recipient = "test-app.near";
    const callbackUrl = "https://example.com/callback";
    const specificNonce = generateNonce();

    const signOptions: SignOptions = {
      signer: FCAK_KEY_PAIR,
      accountId: ACCOUNT_ID,
      recipient,
      data: appData,
      callbackUrl,
      nonce: specificNonce,
    };

    const authTokenString: string = await sign(signOptions);
    expect(authTokenString).toBeDefined();
    expect(typeof authTokenString).toBe("string");

    // Verify the authTokenString
    const verificationResult: VerificationResult = await verify(authTokenString, {
      expectedRecipient: recipient,
      requireFullAccessKey: false, // FCAK is not a FAK
    });

    expect(verificationResult).toBeDefined();
    expect(verificationResult.accountId).toBe(ACCOUNT_ID);
    expect(verificationResult.publicKey).toBe(FCAK_PUBLIC_KEY_STR);
    expect(verificationResult.callbackUrl).toBe(callbackUrl);
    expect(verificationResult.messageData.recipient).toBe(recipient);
    expect(verificationResult.messageData.data).toEqual(appData);
    expect(verificationResult.messageData.nonce).toBe(uint8ArrayToBase64(specificNonce));
    expect(typeof verificationResult.messageData.timestamp).toBe("number");

    // Optionally, parse the token directly to check raw NearAuthData
    const parsedNearAuthData: NearAuthData = parseAuthToken(authTokenString);
    expect(parsedNearAuthData.account_id).toBe(ACCOUNT_ID);
    expect(parsedNearAuthData.public_key).toBe(FCAK_PUBLIC_KEY_STR);
    expect(parsedNearAuthData.recipient).toBe(recipient);
    expect(parsedNearAuthData.callback_url).toBe(callbackUrl);
    expect(uint8ArrayToBase64(parsedNearAuthData.nonce)).toBe(uint8ArrayToBase64(specificNonce));
  });

  it("should sign using a generated nonce if none is provided", async () => {
    const appData = { info: "Another test message" };
    const recipient = "another-app.near";

    const signOptions: SignOptions = {
      signer: FCAK_KEY_PAIR,
      accountId: ACCOUNT_ID,
      recipient,
      data: appData,
      // No nonce provided
    };

    const authTokenString: string = await sign(signOptions);
    expect(authTokenString).toBeDefined();

    const verificationResult: VerificationResult = await verify(authTokenString, {
      expectedRecipient: recipient,
      requireFullAccessKey: false,
    });

    expect(verificationResult).toBeDefined();
    expect(verificationResult.accountId).toBe(ACCOUNT_ID);
    expect(verificationResult.messageData.recipient).toBe(recipient);
    expect(verificationResult.messageData.data).toEqual(appData);
    expect(typeof verificationResult.messageData.nonce).toBe("string"); // Nonce is base64 string in MessageData
    expect(verificationResult.messageData.nonce.length).toBeGreaterThan(0); // Check if nonce was generated
    expect(typeof verificationResult.messageData.timestamp).toBe("number");

    // Check raw parsed data
    const parsedNearAuthData: NearAuthData = parseAuthToken(authTokenString);
    expect(parsedNearAuthData.nonce).toBeInstanceOf(Uint8Array);
    expect(parsedNearAuthData.nonce.length).toBe(32);
  });
});
