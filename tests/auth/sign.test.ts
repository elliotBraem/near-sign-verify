import * as near from "near-api-js";
import dotenv from "dotenv";
import { beforeAll, describe, expect, it } from "vitest";
import {
  generateNonce,
  NearAuthData,
  parseAuthToken,
  sign,
  SignOptions,
  VerificationResult,
  verify,
} from "../../src/index.js";

dotenv.config();

const accountId = "signverifytests.testnet";
const FCAK_publicKey_STR =
  "ed25519:DKFEx1W5rxMNVAnqJ25Cq47Xvys4zZsrJg8bzgT971vt";
let FCAK_KEY_PAIR: near.KeyPair;

describe("Sign Function", () => {
  beforeAll(() => {
    const fcakSecretKey = process.env.FCAK_SECRET_KEY!;
    if (!fcakSecretKey) {
      throw new Error(
        "FCAK_SECRET_KEY not found in environment variables. Please ensure .env file is set up correctly.",
      );
    }
    FCAK_KEY_PAIR = near.KeyPair.fromString(
      fcakSecretKey as near.utils.KeyPairString,
    );
    if (FCAK_KEY_PAIR.getPublicKey().toString() !== FCAK_publicKey_STR) {
      throw new Error(
        "Provided FCAK_SECRET_KEY does not match FCAK_publicKey_STR.",
      );
    }
  });

  it("should sign a message with KeyPair and produce a verifiable auth token", async () => {
    const appData = { info: "Test message for signing" };
    const recipient = "test-app.near";
    const callbackUrl = "https://example.com/callback";
    const specificNonce = generateNonce();

    const signOptions: SignOptions = {
      signer: FCAK_KEY_PAIR.toString(),
      accountId: accountId,
      recipient,
      callbackUrl,
      nonce: specificNonce,
    };

    const authTokenString: string = await sign(
      JSON.stringify(appData),
      signOptions,
    );
    expect(authTokenString).toBeDefined();
    expect(typeof authTokenString).toBe("string");

    // Verify the authTokenString
    const verificationResult: VerificationResult = await verify(
      authTokenString,
      {
        expectedRecipient: recipient,
        requireFullAccessKey: false, // FCAK is not a FAK
      },
    );

    expect(verificationResult).toBeDefined();
    expect(verificationResult.accountId).toBe(accountId);
    expect(verificationResult.publicKey).toBe(FCAK_publicKey_STR);
    expect(verificationResult.callbackUrl).toBe(callbackUrl);
    expect(verificationResult.message).toEqual(JSON.stringify(appData));

    // Optionally, parse the token directly to check raw NearAuthData
    const parsedNearAuthData: NearAuthData = parseAuthToken(authTokenString);
    expect(parsedNearAuthData.accountId).toBe(accountId);
    expect(parsedNearAuthData.publicKey).toBe(FCAK_publicKey_STR);
    expect(parsedNearAuthData.recipient).toBe(recipient);
    expect(parsedNearAuthData.callbackUrl).toBe(callbackUrl);
    expect(new Uint8Array(parsedNearAuthData.nonce)).toStrictEqual(
      specificNonce,
    );
  });

  it("should sign using a generated nonce if none is provided", async () => {
    const recipient = "another-app.near";

    const signOptions: SignOptions<Uint8Array> = {
      signer: FCAK_KEY_PAIR.toString(),
      accountId: accountId,
      recipient,
      // No nonce provided
    };

    const authTokenString: string = await sign(
      "Another test message",
      signOptions,
    );
    expect(authTokenString).toBeDefined();

    const verificationResult: VerificationResult = await verify(
      authTokenString,
      {
        expectedRecipient: recipient,
        requireFullAccessKey: false,
      },
    );

    expect(verificationResult).toBeDefined();
    expect(verificationResult.accountId).toBe(accountId);

    // Check raw parsed data
    const parsedNearAuthData: NearAuthData = parseAuthToken(authTokenString);
    expect(parsedNearAuthData.nonce.length).toBe(32);
  });

  it("should sign with a string nonce", async () => {
    const recipient = "string-nonce-app.near";
    const stringNonce = "test-nonce-123456";

    const signOptions: SignOptions<string> = {
      signer: FCAK_KEY_PAIR.toString(),
      accountId: accountId,
      recipient,
      nonce: stringNonce,
    };

    const authTokenString: string = await sign(
      "String nonce test message",
      signOptions,
    );
    expect(authTokenString).toBeDefined();

    // Verify with custom nonce validation
    const verificationResult: VerificationResult = await verify(
      authTokenString,
      {
        expectedRecipient: recipient,
        requireFullAccessKey: false,
        validateNonce: (nonce) => {
          // The nonce in verification will be a Uint8Array
          const decoder = new TextDecoder();
          const decodedNonce = decoder.decode(nonce as Uint8Array);
          return decodedNonce.includes(stringNonce);
        },
      },
    );

    expect(verificationResult).toBeDefined();
    expect(verificationResult.accountId).toBe(accountId);
  });

  it("should sign with a number nonce", async () => {
    const recipient = "number-nonce-app.near";
    const numberNonce = 12345678;

    const signOptions: SignOptions<number> = {
      signer: FCAK_KEY_PAIR.toString(),
      accountId: accountId,
      recipient,
      nonce: numberNonce,
    };

    const authTokenString: string = await sign(
      "Number nonce test message",
      signOptions,
    );
    expect(authTokenString).toBeDefined();

    // Verify with custom nonce validation
    const verificationResult: VerificationResult = await verify(
      authTokenString,
      {
        expectedRecipient: recipient,
        requireFullAccessKey: false,
        validateNonce: (nonce) => {
          // The nonce in verification will be a Uint8Array
          const decoder = new TextDecoder();
          const decodedNonce = decoder.decode(nonce as Uint8Array);
          return decodedNonce.includes(numberNonce.toString());
        },
      },
    );

    expect(verificationResult).toBeDefined();
    expect(verificationResult.accountId).toBe(accountId);
  });

  it("should sign with a Buffer nonce", async () => {
    // Skip test if Buffer is not available (browser environment)
    if (typeof Buffer === "undefined") {
      return;
    }

    const recipient = "buffer-nonce-app.near";
    const bufferNonce = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

    const signOptions: SignOptions<Buffer> = {
      signer: FCAK_KEY_PAIR.toString(),
      accountId: accountId,
      recipient,
      nonce: bufferNonce,
    };

    const authTokenString: string = await sign<Buffer>(
      "Buffer nonce test message",
      signOptions,
    );
    expect(authTokenString).toBeDefined();

    // Verify with custom nonce validation
    const verificationResult: VerificationResult = await verify(
      authTokenString,
      {
        expectedRecipient: recipient,
        requireFullAccessKey: false,
        validateNonce: (nonce) => {
          // The nonce in verification will be a Uint8Array
          // Check if the first 10 bytes match our original buffer
          const nonceArray = nonce as Uint8Array;
          for (let i = 0; i < bufferNonce.length; i++) {
            if (nonceArray[i] !== bufferNonce[i]) {
              return false;
            }
          }
          return true;
        },
      },
    );

    expect(verificationResult).toBeDefined();
    expect(verificationResult.accountId).toBe(accountId);

    // Parse the token to check the raw nonce data
    const parsedNearAuthData: NearAuthData = parseAuthToken(authTokenString);
    const nonceFromToken = new Uint8Array(parsedNearAuthData.nonce);
    expect(nonceFromToken.length).toBe(32); // Should be padded to 32 bytes

    // Check that the first bytes match our original buffer
    for (let i = 0; i < bufferNonce.length; i++) {
      expect(nonceFromToken[i]).toBe(bufferNonce[i]);
    }
  });
});
