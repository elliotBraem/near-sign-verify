import { describe, it, expect } from "vitest";
import { parseAuthToken } from "../../src/auth/parseAuthToken.js";
import type { NearAuthData } from "../../src/types.js";

describe("parseAuthToken", () => {
  it("should parse a valid auth token", () => {
    const authData: NearAuthData = {
      account_id: "test.near",
      public_key: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
      signature: "base64signature",
      message: "Hello, world!",
      nonce: "1609459200000",
      recipient: "recipient.near",
    };

    const token = JSON.stringify(authData);
    const parsed = parseAuthToken(token);

    expect(parsed).toEqual(authData);
  });

  it("should handle optional fields", () => {
    const authData: NearAuthData = {
      account_id: "test.near",
      public_key: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
      signature: "base64signature",
      message: "Hello, world!",
      nonce: "1609459200000",
      recipient: "recipient.near",
      callback_url: "https://example.com/callback",
      state: "some-state-value",
    };

    const token = JSON.stringify(authData);
    const parsed = parseAuthToken(token);

    expect(parsed).toEqual(authData);
    expect(parsed.callback_url).toBe("https://example.com/callback");
    expect(parsed.state).toBe("some-state-value");
  });

  it("should throw an error for invalid JSON", () => {
    const invalidToken = "{invalid-json";

    expect(() => parseAuthToken(invalidToken)).toThrow(
      "Invalid auth token format",
    );
  });

  it("should throw an error for missing required fields", () => {
    const invalidData = {
      public_key: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
      signature: "base64signature",
      message: "Hello, world!",
      nonce: "1609459200000",
      recipient: "recipient.near",
    };

    const token = JSON.stringify(invalidData);

    expect(() => parseAuthToken(token)).toThrow("Invalid auth data");
  });

  it("should throw an error for missing recipient field", () => {
    const invalidData = {
      account_id: "test.near",
      public_key: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
      signature: "base64signature",
      message: "Hello, world!",
      nonce: "1609459200000",
    };

    const token = JSON.stringify(invalidData);

    expect(() => parseAuthToken(token)).toThrow("Invalid auth data");
  });
});
