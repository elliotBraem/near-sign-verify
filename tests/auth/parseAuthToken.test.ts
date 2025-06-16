import { describe, expect, it } from "vitest";
import { createAuthToken } from "../../src/auth/createAuthToken.js";
import { parseAuthToken } from "../../src/auth/parseAuthToken.js";
import type { NearAuthData } from "../../src/schemas.js";

describe("parseAuthToken", () => {
  it("should handle optional fields", () => {
    const authData: NearAuthData = {
      account_id: "test.near",
      public_key: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
      signature: "base64signature",
      message: "Hello, world!",
      nonce: Array(32).fill(0),
      recipient: "recipient.near",
      callback_url: "https://example.com/callback",
      state: null,
    };

    const token = createAuthToken(authData);
    const parsed = parseAuthToken(token);

    expect(parsed.account_id).toEqual(authData.account_id);
    expect(parsed.public_key).toEqual(authData.public_key);
    expect(parsed.signature).toEqual(authData.signature);
    expect(parsed.message).toEqual(authData.message);
    expect(parsed.nonce).toEqual(authData.nonce);
    expect(parsed.recipient).toEqual(authData.recipient);
    expect(parsed.callback_url).toEqual(authData.callback_url);
    expect(parsed.callback_url).toBe("https://example.com/callback");
  });

  it("should throw an error for invalid token format", () => {
    const invalidToken = "invalid-base64-data";

    expect(() => parseAuthToken(invalidToken)).toThrow(
      "Invalid auth token: padding",
    );
  });

  it("should handle corrupted token data gracefully", () => {
    // Create a valid token first
    const authData: NearAuthData = {
      account_id: "test.near",
      public_key: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
      signature: "base64signature",
      message: "Hello, world!",
      nonce: Array(32).fill(0),
      recipient: "recipient.near",
      callback_url: null,
      state: null,
    };

    const token = createAuthToken(authData);

    // Corrupt the token by replacing some characters
    const corruptedToken = token.substring(0, token.length - 10) + "XXXXXXXXXX";

    // Zorsh may successfully parse corrupted data but with garbled fields
    const parsed = parseAuthToken(corruptedToken);

    // The account_id should be preserved (it comes early in the serialization)
    expect(parsed.account_id).toBe("test.near");

    // But the recipient field (which comes later) should be corrupted
    expect(parsed.recipient).not.toBe("recipient.near");
  });
});
