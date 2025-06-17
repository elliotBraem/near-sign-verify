import { describe, expect, it } from "vitest";
import { createAuthToken } from "../../src/auth/createAuthToken.js";
import { parseAuthToken } from "../../src/auth/parseAuthToken.js";
import type { NearAuthData } from "../../src/schemas.js";

describe("parseAuthToken", () => {
  it("should handle optional fields", () => {
    const authData: NearAuthData = {
      accountId: "test.near",
      publicKey: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
      signature: "base64signature",
      message: "Hello, world!",
      nonce: Array(32).fill(0),
      recipient: "recipient.near",
      callbackUrl: "https://example.com/callback",
      state: null,
    };

    const token = createAuthToken(authData);
    const parsed = parseAuthToken(token);

    expect(parsed.accountId).toEqual(authData.accountId);
    expect(parsed.publicKey).toEqual(authData.publicKey);
    expect(parsed.signature).toEqual(authData.signature);
    expect(parsed.message).toEqual(authData.message);
    expect(parsed.nonce).toEqual(authData.nonce);
    expect(parsed.recipient).toEqual(authData.recipient);
    expect(parsed.callbackUrl).toEqual(authData.callbackUrl);
    expect(parsed.callbackUrl).toBe("https://example.com/callback");
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
      accountId: "test.near",
      publicKey: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
      signature: "base64signature",
      message: "Hello, world!",
      nonce: Array(32).fill(0),
      recipient: "recipient.near",
      callbackUrl: null,
      state: null,
    };

    const token = createAuthToken(authData);

    // Corrupt the token by replacing some characters
    const corruptedToken = token.substring(0, token.length - 10) + "XXXXXXXXXX";

    // Zorsh may successfully parse corrupted data but with garbled fields
    const parsed = parseAuthToken(corruptedToken);

    // The accountId should be preserved (it comes early in the serialization)
    expect(parsed.accountId).toBe("test.near");

    // But the recipient field (which comes later) should be corrupted
    expect(parsed.recipient).not.toBe("recipient.near");
  });
});
