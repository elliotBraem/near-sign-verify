import { describe, expect, it } from "vitest";
import { parseAuthToken } from "../../src/auth/parseAuthToken.js";
import { uint8ArrayToBase64 } from "../../src/utils/encoding.js";
import * as borsh from "borsh";

describe("parseAuthToken - Edge Cases", () => {
  it("should handle Zod validation errors for invalid data types", () => {
    // Create a token with invalid data types that will pass Borsh but fail Zod
    const invalidBorshData = {
      account_id: 123, // Should be string
      public_key: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
      signature: "base64signature",
      message: "Hello, world!",
      nonce: Array.from(new Uint8Array(32).fill(0)),
      recipient: "recipient.near",
      callback_url: null,
    };

    const schema = {
      struct: {
        account_id: "u32", // Wrong type - should be string
        public_key: "string",
        signature: "string",
        message: "string",
        nonce: { array: { type: "u8", len: 32 } },
        recipient: "string",
        callback_url: { option: "string" },
      },
    };

    const serialized = borsh.serialize(schema, invalidBorshData);
    const token = uint8ArrayToBase64(serialized);

    expect(() => parseAuthToken(token)).toThrow("Invalid auth token:");
  });

  it("should handle missing required fields", () => {
    // Create a token missing required fields
    const incompleteBorshData = {
      account_id: "test.near",
      public_key: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
      // missing signature, message, nonce, recipient
      callback_url: null,
    };

    const schema = {
      struct: {
        account_id: "string",
        public_key: "string",
        callback_url: { option: "string" },
      },
    };

    const serialized = borsh.serialize(schema, incompleteBorshData);
    const token = uint8ArrayToBase64(serialized);

    expect(() => parseAuthToken(token)).toThrow("Invalid auth token:");
  });

  it("should handle non-Error exceptions", () => {
    // Create an invalid token that will cause a non-Error exception
    const invalidToken = "not-valid-base64-!@#$%";

    expect(() => parseAuthToken(invalidToken)).toThrow("Invalid auth token:");
  });

  it("should handle empty token", () => {
    expect(() => parseAuthToken("")).toThrow("Invalid auth token:");
  });

  it("should handle malformed base64", () => {
    const malformedBase64 = "SGVsbG8gV29ybGQ!"; // Invalid base64 character
    expect(() => parseAuthToken(malformedBase64)).toThrow("Invalid auth token:");
  });
});
