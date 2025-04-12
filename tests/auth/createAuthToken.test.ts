import { describe, it, expect } from "vitest";
import { createAuthToken } from "../../src/auth/createAuthToken.js";
import { parseAuthToken } from "../../src/auth/parseAuthToken.js";
import type { NearAuthData } from "../../src/types.js";

describe("createAuthToken", () => {
  it("should create a properly formatted auth token that can be parsed back", () => {
    const authData: NearAuthData = {
      account_id: "test.near",
      public_key: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
      signature: "base64signature",
      message: "Hello, world!",
      nonce: "1609459200000",
      recipient: "recipient.near",
    };

    const token = createAuthToken(authData);

    // Token should be a string
    expect(typeof token).toBe("string");

    // Should be able to parse it back
    const parsed = parseAuthToken(token);

    // Compare essential fields (ignoring null optional fields)
    expect(parsed.account_id).toEqual(authData.account_id);
    expect(parsed.public_key).toEqual(authData.public_key);
    expect(parsed.signature).toEqual(authData.signature);
    expect(parsed.message).toEqual(authData.message);
    expect(parsed.nonce).toEqual(authData.nonce);
    expect(parsed.recipient).toEqual(authData.recipient);
  });

  it("should include callback_url when provided", () => {
    const authData: NearAuthData = {
      account_id: "test.near",
      public_key: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
      signature: "base64signature",
      message: "Hello, world!",
      nonce: "1609459200000",
      recipient: "recipient.near",
      callback_url: "https://example.com/callback",
    };

    const token = createAuthToken(authData);

    // Should be able to parse it back with callback_url
    const parsed = parseAuthToken(token);
    expect(parsed.callback_url).toBe("https://example.com/callback");
  });
});
