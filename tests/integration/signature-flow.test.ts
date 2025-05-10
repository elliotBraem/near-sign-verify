import { describe, it, expect } from "vitest";
import * as near from "near-api-js";
import { sha256 } from "@noble/hashes/sha2";
import * as borsh from "borsh";
import {
  generateNonce,
  validateSignature,
  uint8ArrayToBase64,
  TAG,
  NearAuthData,
} from "../../src/index.js";

describe("NEAR Signature Flow Integration Test", () => {
  it("should generate a valid signature that passes validation", async () => {
    // Setup test data
    const message = "Post";
    const nonce = generateNonce();
    const recipient = "crosspost.near";
    const accountId = "test.near";
    
    // Create a test key pair
    const keyPair = near.KeyPair.fromRandom("ed25519");
    const privateKey = keyPair.toString();
    const publicKey = keyPair.getPublicKey().toString();
    
    // Create the payload with the same structure as in the code snippet
    const payload = {
      tag: TAG,
      message,
      nonce: Array.from(nonce),
      receiver: recipient,
      callback_url: null,
    };
    
    // Use the same Borsh schema as in serializePayload
    const schema = {
      struct: {
        tag: "u32",
        message: "string",
        nonce: { array: { type: "u8", len: 32 } },
        receiver: "string",
        callback_url: { option: "string" },
      },
    };
    
    // Serialize the payload
    const serializedPayload = borsh.serialize(schema, payload);
    
    // Hash the serialized payload
    const payloadHash = sha256(serializedPayload);
    
    // Sign the hashed payload
    const signedMessage = keyPair.sign(payloadHash);
    
    // Create the auth data object
    const authData: NearAuthData = {
      message,
      nonce,
      recipient,
      callback_url: "",
      signature: uint8ArrayToBase64(signedMessage.signature),
      account_id: accountId,
      public_key: publicKey,
    };
    
    // Validate the signature
    const validationResult = await validateSignature(authData);
    
    // Assert that the signature is valid
    expect(validationResult.valid).toBe(true);
    expect(validationResult.error).toBeUndefined();
  });
  
  it("should detect an invalid signature", async () => {
    // Setup test data
    const message = "Post";
    const nonce = generateNonce();
    const recipient = "crosspost.near";
    const accountId = "test.near";
    
    // Create a test key pair
    const keyPair = near.KeyPair.fromRandom("ed25519");
    const publicKey = keyPair.getPublicKey().toString();
    
    // Create a different key pair for signing (to create an invalid signature)
    const wrongKeyPair = near.KeyPair.fromRandom("ed25519");
    
    // Create the payload
    const payload = {
      tag: TAG,
      message,
      nonce: Array.from(nonce),
      receiver: recipient,
      callback_url: null,
    };
    
    // Use the same Borsh schema
    const schema = {
      struct: {
        tag: "u32",
        message: "string",
        nonce: { array: { type: "u8", len: 32 } },
        receiver: "string",
        callback_url: { option: "string" },
      },
    };
    
    // Serialize the payload
    const serializedPayload = borsh.serialize(schema, payload);
    
    // Hash the serialized payload
    const payloadHash = new Uint8Array(sha256(serializedPayload));
    
    // Sign with the wrong key pair
    const signedMessage = wrongKeyPair.sign(payloadHash);
    
    // Create the auth data object with mismatched public key and signature
    const authData: NearAuthData = {
      message,
      nonce,
      recipient,
      callback_url: "",
      signature: uint8ArrayToBase64(signedMessage.signature),
      account_id: accountId,
      public_key: publicKey, // Using the original key pair's public key
    };
    
    // Validate the signature
    const validationResult = await validateSignature(authData);
    
    // Assert that the signature is invalid
    expect(validationResult.valid).toBe(false);
    expect(validationResult.error).toBe("Invalid signature");
  });
  
  it("should match the exact flow from the code snippet", async () => {
    // This test follows the exact flow from the provided code snippet
    const message = "Post";
    const nonce = generateNonce();
    const recipient = "crosspost.near";
    const accountId = "efiz.near";
    
    // Create a test key pair (simulating the config.keyPair)
    const keyPair = near.KeyPair.fromRandom("ed25519");
    const privateKey = keyPair.toString();
    const publicKey = keyPair.getPublicKey().toString();
    
    // Create the payload with the same structure as in the code snippet
    const payload = {
      tag: TAG,
      message,
      nonce: Array.from(nonce),
      receiver: recipient,
      callback_url: null,
    };
    
    // Use the same Borsh schema as in serializePayload
    const schema = {
      struct: {
        tag: "u32",
        message: "string",
        nonce: { array: { type: "u8", len: 32 } },
        receiver: "string",
        callback_url: { option: "string" },
      },
    };
    
    // Serialize the payload
    const serializedPayload = borsh.serialize(schema, payload);
    
    // Hash the serialized payload
    const payloadHash = new Uint8Array(sha256(serializedPayload));
    
    // Sign the hashed payload
    const signedMessage = keyPair.sign(payloadHash);
    
    // Create the auth data object
    const authData: NearAuthData = {
      message,
      nonce,
      recipient,
      callback_url: "",
      signature: uint8ArrayToBase64(signedMessage.signature),
      account_id: accountId,
      public_key: publicKey,
    };
    
    // Validate the signature
    const validationResult = await validateSignature(authData);
    
    // Assert that the signature is valid
    expect(validationResult.valid).toBe(true);
    expect(validationResult.error).toBeUndefined();
  });
});
