import { describe, it, expect, beforeAll } from "vitest";
import * as near from "near-api-js";
import { sha256 } from "@noble/hashes/sha2";
import * as borsh from "borsh";
import dotenv from "dotenv";
import {
  generateNonce,
  verify,
  uint8ArrayToBase64,
  TAG,
  NearAuthData,
  VerifyOptions,
} from "../../src/index.js";
import { KeyPairString } from "near-api-js/lib/utils/key_pair.js";

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

    FAK_KEY_PAIR = near.KeyPair.fromString(fakSecretKey as KeyPairString);
    FCAK_KEY_PAIR = near.KeyPair.fromString(fcakSecretKey as KeyPairString);

    if (FAK_KEY_PAIR.getPublicKey().toString() !== FAK_PUBLIC_KEY) {
      throw new Error("Provided FAK_SECRET_KEY does not match FAK_PUBLIC_KEY.");
    }
    if (FCAK_KEY_PAIR.getPublicKey().toString() !== FCAK_PUBLIC_KEY) {
      throw new Error(
        "Provided FCAK_SECRET_KEY does not match FCAK_PUBLIC_KEY.",
      );
    }
  });

  const createTestPayload = (
    message: string,
    nonce: Uint8Array,
    recipient: string,
    callback_url: string | null = null,
  ) => {
    return {
      tag: TAG,
      message,
      nonce: Array.from(nonce), // Borsh schema expects array for nonce
      receiver: recipient,
      callback_url,
    };
  };

  const schema = {
    struct: {
      tag: "u32",
      message: "string",
      nonce: { array: { type: "u8", len: 32 } },
      receiver: "string",
      callback_url: { option: "string" },
    },
  };

  it("should detect an invalid signature (wrong key used for signing)", async () => {
    const message = "Test wrong key";
    const nonce = generateNonce();
    const recipient = "someapp.near";

    // Intended signer (e.g., our FCAK)
    const intendedPublicKey = FCAK_PUBLIC_KEY;
    const intendedAccountId = SIGNVERIFYTESTS_ACCOUNT_ID;

    // Actual signer (a different random key)
    const wrongKeyPair = near.KeyPair.fromRandom("ed25519");

    const payload = createTestPayload(message, nonce, recipient);
    const serializedPayload = borsh.serialize(schema, payload);
    const payloadHash = sha256(serializedPayload);
    const signedMessage = wrongKeyPair.sign(payloadHash); // Signed with wrong key

    const authData: NearAuthData = {
      message,
      // @ts-expect-error near-api-js type issue with noble-hashes, expects Uint8Array<ArrayBuffer>
      nonce,
      recipient,
      callback_url: "",
      signature: uint8ArrayToBase64(signedMessage.signature),
      account_id: intendedAccountId,
      public_key: intendedPublicKey, // Public key of the intended signer
    };

    const validationResult = await verify(authData);

    expect(validationResult.valid).toBe(false);
    expect(validationResult.error).toBe(
      "Public key does not belong to the specified account or does not meet access requirements.",
    );
  });

  it("should succeed when using FAK for signverifytests.testnet and requireFullAccessKey: true", async () => {
    const message = "Test with FAK";
    const nonce = generateNonce();
    const recipient = "someapp.near";

    const payload = createTestPayload(message, nonce, recipient);
    const serializedPayload = borsh.serialize(schema, payload);
    const payloadHash = sha256(serializedPayload);
    const signedMessage = FAK_KEY_PAIR.sign(payloadHash);

    const authData: NearAuthData = {
      message,
      // @ts-expect-error near-api-js type issue with noble-hashes, expects Uint8Array<ArrayBuffer>
      nonce,
      recipient,
      callback_url: "",
      signature: uint8ArrayToBase64(signedMessage.signature),
      account_id: SIGNVERIFYTESTS_ACCOUNT_ID,
      public_key: FAK_PUBLIC_KEY,
    };

    const validationResult = await verify(authData); // requireFullAccessKey defaults to true

    expect(validationResult.valid).toBe(true);
  });

  it("should fail when using FCAK for signverifytests.testnet and requireFullAccessKey: true", async () => {
    const message = "Test with FCAK, requireFullAccessKey=true";
    const nonce = generateNonce();
    const recipient = "someapp.near";

    const payload = createTestPayload(message, nonce, recipient);
    const serializedPayload = borsh.serialize(schema, payload);
    const payloadHash = sha256(serializedPayload);
    const signedMessage = FCAK_KEY_PAIR.sign(payloadHash);

    const authData: NearAuthData = {
      message,
      // @ts-expect-error near-api-js type issue with noble-hashes, expects Uint8Array<ArrayBuffer>
      nonce,
      recipient,
      callback_url: "",
      signature: uint8ArrayToBase64(signedMessage.signature),
      account_id: SIGNVERIFYTESTS_ACCOUNT_ID,
      public_key: FCAK_PUBLIC_KEY,
    };

    const options: VerifyOptions = { requireFullAccessKey: true };
    const validationResult = await verify(authData, options);

    expect(validationResult.valid).toBe(false);
    expect(validationResult.error).toBe(
      "Public key does not belong to the specified account or does not meet access requirements.",
    );
  });

  it("should succeed when using FCAK for signverifytests.testnet and requireFullAccessKey: false", async () => {
    const message = "Test with FCAK, requireFullAccessKey=false";
    const nonce = generateNonce();
    const recipient = "someapp.near";

    const payload = createTestPayload(message, nonce, recipient);
    const serializedPayload = borsh.serialize(schema, payload);
    const payloadHash = sha256(serializedPayload);
    const signedMessage = FCAK_KEY_PAIR.sign(payloadHash);

    const authData: NearAuthData = {
      message,
      // @ts-expect-error near-api-js type issue with noble-hashes, expects Uint8Array<ArrayBuffer>
      nonce,
      recipient,
      callback_url: "",
      signature: uint8ArrayToBase64(signedMessage.signature),
      account_id: SIGNVERIFYTESTS_ACCOUNT_ID,
      public_key: FCAK_PUBLIC_KEY,
    };

    const options: VerifyOptions = { requireFullAccessKey: false };
    const validationResult = await verify(authData, options);

    expect(validationResult.valid).toBe(true);
  });

  it("should fail for a random public key not associated with any account", async () => {
    const message = "Test with random unassociated PK";
    const nonce = generateNonce();
    const recipient = "someapp.near";
    const namedAccountId = "somerandomuser.testnet"; // A named account

    const randomKeyPair = near.KeyPair.fromRandom("ed25519");
    const randomPublicKey = randomKeyPair.getPublicKey().toString();

    const payload = createTestPayload(message, nonce, recipient);
    const serializedPayload = borsh.serialize(schema, payload);
    const payloadHash = sha256(serializedPayload);
    const signedMessage = randomKeyPair.sign(payloadHash);

    const authData: NearAuthData = {
      message,
      // @ts-expect-error near-api-js type issue with noble-hashes, expects Uint8Array<ArrayBuffer>
      nonce,
      recipient,
      callback_url: "",
      signature: uint8ArrayToBase64(signedMessage.signature),
      account_id: namedAccountId,
      public_key: randomPublicKey,
    };

    const validationResult = await verify(authData);

    expect(validationResult.valid).toBe(false);
    expect(validationResult.error).toBe(
      "Public key does not belong to the specified account or does not meet access requirements.",
    );
  });
});
