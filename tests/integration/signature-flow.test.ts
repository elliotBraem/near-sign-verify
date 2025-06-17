import dotenv from "dotenv";
import * as near from "near-api-js";
import { beforeAll, describe, expect, it } from "vitest";
import {
  generateNonce,
  sign,
  SignOptions,
  VerificationResult,
  verify,
  VerifyOptions,
} from "../../src/index.js";

dotenv.config();

const SIGNVERIFYTESTS_ACCOUNT_ID = "signverifytests.testnet";
const FAK_PUBLIC_KEY = "ed25519:BpWbZD6PJkG1FSkpububwAxVx62g4ZGjCtq6TsMCBhmD";
const FCAK_PUBLIC_KEY = "ed25519:DKFEx1W5rxMNVAnqJ25Cq47Xvys4zZsrJg8bzgT971vt";

let FAK_KEY_PAIR: near.KeyPair;
let FCAK_KEY_PAIR: near.KeyPair;

describe("NEAR Signature Flow Integration Test", () => {
  beforeAll(() => {
    const fakSecretKey = process.env.FAK_SECRET_KEY!;
    const fcakSecretKey = process.env.FCAK_SECRET_KEY!;

    if (!fakSecretKey) {
      throw new Error(
        "FAK_SECRET_KEY not found in environment variables. Please ensure .env file is set up correctly and contains FAK_SECRET_KEY.",
      );
    }
    if (!fcakSecretKey) {
      throw new Error(
        "FCAK_SECRET_KEY not found in environment variables. Please ensure .env file is set up correctly and contains FCAK_SECRET_KEY.",
      );
    }

    FAK_KEY_PAIR = near.KeyPair.fromString(
      fakSecretKey as near.utils.KeyPairString,
    );
    FCAK_KEY_PAIR = near.KeyPair.fromString(
      fcakSecretKey as near.utils.KeyPairString,
    );

    if (FAK_KEY_PAIR.getPublicKey().toString() !== FAK_PUBLIC_KEY) {
      throw new Error("Provided FAK_SECRET_KEY does not match FAK_PUBLIC_KEY.");
    }
    if (FCAK_KEY_PAIR.getPublicKey().toString() !== FCAK_PUBLIC_KEY) {
      throw new Error(
        "Provided FCAK_SECRET_KEY does not match FCAK_PUBLIC_KEY.",
      );
    }
  });

  it("should detect an invalid signature (wrong key used for signing, but claimed accountId)", async () => {
    const recipient = "someapp.near";
    const callbackUrl = "https://example.com/wrongkey";
    const specificNonce = generateNonce();

    const intendedAccountId = SIGNVERIFYTESTS_ACCOUNT_ID;
    const wrongKeyPair = near.KeyPair.fromRandom("ed25519");

    const signOptions: SignOptions = {
      signer: wrongKeyPair.toString(), // Signing with this wrong key
      accountId: intendedAccountId, // But claiming this account ID
      recipient,
      nonce: specificNonce,
      callbackUrl,
    };

    const authTokenString = await sign("Test wrong key", signOptions);

    await expect(
      verify(authTokenString, { expectedRecipient: recipient }),
    ).rejects.toThrowError(/Public key ownership verification failed/);
  });

  it("should succeed when using FAK and requireFullAccessKey: true", async () => {
    const recipient = "someapp.near";
    const callbackUrl = "https://example.com/fak";
    const specificNonce = generateNonce();

    const signOptions: SignOptions = {
      signer: FAK_KEY_PAIR.toString(),
      accountId: SIGNVERIFYTESTS_ACCOUNT_ID,
      recipient,
      nonce: specificNonce,
      callbackUrl,
    };
    const authTokenString = await sign("Test with FAK", signOptions);

    const verificationResult: VerificationResult = await verify(
      authTokenString,
      {
        expectedRecipient: recipient,
        // requireFullAccessKey: true is default
      },
    );
    expect(verificationResult.accountId).toBe(SIGNVERIFYTESTS_ACCOUNT_ID);
  });

  it("should fail when using FCAK and requireFullAccessKey: true", async () => {
    const appData = { detail: "Test with FCAK, requireFullAccessKey=true" };
    const recipient = "someapp.near";
    const specificNonce = generateNonce();

    const signOptions: SignOptions = {
      signer: FCAK_KEY_PAIR.toString(),
      accountId: SIGNVERIFYTESTS_ACCOUNT_ID,
      recipient,
      nonce: specificNonce,
    };
    const authTokenString = await sign(
      "Test with FCAK, requireFullAccessKey=true",
      signOptions,
    );

    const verifyOpts: VerifyOptions = {
      requireFullAccessKey: true,
      expectedRecipient: recipient,
    };
    await expect(verify(authTokenString, verifyOpts)).rejects.toThrowError(
      /Public key ownership verification failed/,
    );
  });

  it("should succeed when using FCAK and requireFullAccessKey: false", async () => {
    const recipient = "someapp.near";
    const specificNonce = generateNonce();

    const signOptions: SignOptions = {
      signer: FCAK_KEY_PAIR.toString(),
      accountId: SIGNVERIFYTESTS_ACCOUNT_ID,
      recipient,
      nonce: specificNonce,
    };
    const authTokenString = await sign(
      "Test with FCAK, requireFullAccessKey=false",
      signOptions,
    );

    const verifyOpts: VerifyOptions = {
      requireFullAccessKey: false,
      expectedRecipient: recipient,
    };
    const verificationResult = await verify(authTokenString, verifyOpts);
    expect(verificationResult.accountId).toBe(SIGNVERIFYTESTS_ACCOUNT_ID);
    expect(verificationResult.message).toEqual(
      "Test with FCAK, requireFullAccessKey=false",
    );
  });

  it("should fail for a random public key not associated with any account", async () => {
    const recipient = "someapp.near";
    const specificNonce = generateNonce();
    const claimedAccountId = "somerandomuser.testnet";

    const randomKeyPair = near.KeyPair.fromRandom("ed25519");

    const signOptions: SignOptions = {
      signer: randomKeyPair.toString(),
      accountId: claimedAccountId,
      recipient,
      nonce: specificNonce,
    };
    const authTokenString = await sign(
      "Test with random unassociated PK",
      signOptions,
    );

    await expect(
      verify(authTokenString, { expectedRecipient: recipient }),
    ).rejects.toThrowError(/Public key ownership verification failed/);
  });
});
