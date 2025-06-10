import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createAuthToken } from "../../src/auth/createAuthToken.js";
import { verify } from "../../src/auth/verify.js";
import * as cryptoModule from "../../src/crypto/crypto.js";
import type { NearAuthData } from "../../src/types.js";
import * as nonceModule from "../../src/utils/nonce.js";

// Mock dependencies
vi.mock("../../src/crypto/crypto.js");
vi.mock("../../src/utils/nonce.js");

// Mock global fetch
global.fetch = vi.fn();

describe("verify - Edge Cases", () => {
  const testNonce = new Uint8Array(32);

  const baseAuthData: NearAuthData = {
    account_id: "testuser.testnet",
    public_key: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
    signature: "base64signature",
    message: "test message",
    nonce: testNonce,
    recipient: "recipient.near",
  };

  beforeEach(() => {
    vi.resetAllMocks();
    // Default successful nonce validation (no throw = success)
    vi.spyOn(nonceModule, "validateNonce").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("should handle malformed auth token string", async () => {
    await expect(verify("invalid-token")).rejects.toThrow(
      "Failed to parse auth token",
    );
  });

  it("should handle FastNEAR API returning unexpected response format", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ unexpected: "format" }), // Missing account_ids array
    });

    const tokenString = createAuthToken(baseAuthData);

    await expect(verify(tokenString)).rejects.toThrow(
      "Public key ownership verification failed: API error or unexpected response",
    );
  });

  it("should handle FastNEAR API returning malformed JSON", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => {
        throw new Error("Invalid JSON");
      },
    });

    const tokenString = createAuthToken(baseAuthData);

    await expect(verify(tokenString)).rejects.toThrow(
      "Public key ownership verification failed: API error or unexpected response",
    );
  });

  it("should handle custom nonce validation throwing an error", async () => {
    const customValidateNonce = vi.fn().mockImplementation(() => {
      throw new Error("Custom validation error");
    });

    const tokenString = createAuthToken(baseAuthData);

    await expect(
      verify(tokenString, {
        validateNonce: customValidateNonce,
      }),
    ).rejects.toThrow("Custom validation error");
  });

  it("should handle very long message data", async () => {
    const longData = "x".repeat(10000); // Very long string

    const authDataWithLongMessage: NearAuthData = {
      ...baseAuthData,
      message: JSON.stringify(longData),
    };

    const tokenString = createAuthToken(authDataWithLongMessage);

    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [baseAuthData.account_id] }),
    });
    vi.spyOn(cryptoModule, "verifySignature").mockResolvedValue(true);

    const result = await verify(tokenString);
    expect(result.message).toBe(JSON.stringify(longData));
  });

  it("should handle message data with complex nested objects", async () => {
    const complexData = {
      user: {
        id: 123,
        profile: {
          name: "Test User",
          settings: {
            theme: "dark",
            notifications: true,
          },
        },
      },
      actions: ["read", "write", "delete"],
      metadata: {
        version: "1.0",
        timestamp: Date.now(),
      },
    };

    const authDataWithComplexMessage: NearAuthData = {
      ...baseAuthData,
      message: JSON.stringify(complexData),
    };

    const tokenString = createAuthToken(authDataWithComplexMessage);

    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [baseAuthData.account_id] }),
    });
    vi.spyOn(cryptoModule, "verifySignature").mockResolvedValue(true);

    const result = await verify(tokenString);
    expect(result.message).toEqual(JSON.stringify(complexData));
  });

  it("should handle account ID with special characters", async () => {
    const specialAccountId = "test-user_123.testnet";
    const specialAuthData: NearAuthData = {
      ...baseAuthData,
      account_id: specialAccountId,
    };

    const tokenString = createAuthToken(specialAuthData);

    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [specialAccountId] }),
    });
    vi.spyOn(cryptoModule, "verifySignature").mockResolvedValue(true);

    const result = await verify(tokenString);
    expect(result.accountId).toBe(specialAccountId);
  });
});
