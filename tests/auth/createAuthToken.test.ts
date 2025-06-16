import { describe, expect, it } from "vitest";
import { createAuthToken } from "../../src/auth/createAuthToken.js";
import { parseAuthToken } from "../../src/auth/parseAuthToken.js";
import type { NearAuthData } from "../../src/schemas.js";

describe("createAuthToken", () => {
  it("should create a properly formatted auth token that can be parsed back", () => {
    const authData: NearAuthData = {
      accountId: "test.near",
      publicKey: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
      signature: "base64signature",
      message: "Hello, world!",
      nonce: Array(32).fill(0),
      recipient: "recipient.near",
      callbackUrl: null,
    };

    const token = createAuthToken(authData);

    // Token should be a string
    expect(typeof token).toBe("string");

    // Should be able to parse it back
    const parsed = parseAuthToken(token);

    // Compare essential fields (ignoring null optional fields)
    expect(parsed.accountId).toEqual(authData.accountId);
    expect(parsed.publicKey).toEqual(authData.publicKey);
    expect(parsed.signature).toEqual(authData.signature);
    expect(parsed.message).toEqual(authData.message);
    expect(parsed.nonce).toEqual(authData.nonce);
    expect(parsed.recipient).toEqual(authData.recipient);
  });

  it("should include callbackUrl when provided", () => {
    const authData: NearAuthData = {
      accountId: "test.near",
      publicKey: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
      signature: "base64signature",
      message: "Hello, world!",
      nonce: Array(32).fill(0),
      recipient: "recipient.near",
      callbackUrl: "https://example.com/callback",
    };

    const token = createAuthToken(authData);

    // Should be able to parse it back with callbackUrl
    const parsed = parseAuthToken(token);
    expect(parsed.callbackUrl).toBe("https://example.com/callback");
  });
});
