import { describe, expect, it } from "vitest";
import { createAuthToken } from "../../src/auth/createAuthToken.js";
import { parseAuthToken } from "../../src/auth/parseAuthToken.js";
import type { NearAuthData } from "../../src/types.js";

describe("parseAuthToken", () => {
  it("should handle optional fields", () => {
    const authData: NearAuthData = {
      account_id: "test.near",
      public_key: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
      signature: "base64signature",
      message: "Hello, world!",
      nonce: new Uint8Array(32).fill(0),
      recipient: "recipient.near",
      callback_url: "https://example.com/callback",
      state: "some-state-value",
    };

    const token = createAuthToken(authData);
    const parsed = parseAuthToken(token);

    expect(parsed).toEqual(authData);
    expect(parsed.callback_url).toBe("https://example.com/callback");
    expect(parsed.state).toBe("some-state-value");
  });

  it("should throw an error for invalid token format", () => {
    const invalidToken = "invalid-base64-data";

    expect(() => parseAuthToken(invalidToken)).toThrow(
      "Invalid auth token: Invalid character",
    );
  });

  it("should throw an error for corrupted token data", () => {
    // Create a valid token first
    const authData: NearAuthData = {
      account_id: "test.near",
      public_key: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
      signature: "base64signature",
      message: "Hello, world!",
      nonce: new Uint8Array(32).fill(0),
      recipient: "recipient.near",
    };

    const token = createAuthToken(authData);

    // Corrupt the token by replacing some characters
    const corruptedToken = token.substring(0, token.length - 5) + "XXXXX";

    expect(() => parseAuthToken(corruptedToken)).toThrow();
  });
});
