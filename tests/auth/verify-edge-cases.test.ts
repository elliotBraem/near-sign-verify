import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { verify } from "../../src/auth/verify.js";
import { createAuthToken } from "../../src/auth/createAuthToken.js";
import * as cryptoModule from "../../src/crypto/crypto.js";
import * as nonceModule from "../../src/utils/nonce.js";
import type { NearAuthData, MessageData } from "../../src/types.js";

// Mock dependencies
vi.mock("../../src/crypto/crypto.js");
vi.mock("../../src/utils/nonce.js");

// Mock global fetch
global.fetch = vi.fn();

describe("verify - Edge Cases", () => {
  const testNonce = new Uint8Array(32);
  
  const messageData: MessageData = {
    nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    timestamp: Date.now(),
    recipient: "recipient.near",
    data: "test data"
  };

  const baseAuthData: NearAuthData = {
    account_id: "testuser.testnet",
    public_key: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
    signature: "base64signature",
    message: JSON.stringify(messageData),
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
      "Failed to parse auth token"
    );
  });

  it("should handle message with extra unexpected fields", async () => {
    const messageWithExtraFields = {
      ...messageData,
      extraField: "should not be here",
      anotherField: 123
    };
    
    const authDataWithExtra: NearAuthData = {
      ...baseAuthData,
      message: JSON.stringify(messageWithExtraFields),
    };
    
    const tokenString = createAuthToken(authDataWithExtra);

    await expect(verify(tokenString)).rejects.toThrow(
      "Unexpected fields in message: extraField, anotherField"
    );
  });

  it("should handle message with wrong field types", async () => {
    const messageWithWrongTypes = {
      nonce: 123, // Should be string
      timestamp: "not-a-number", // Should be number
      recipient: null, // Should be string
      data: "test"
    };
    
    const authDataWithWrongTypes: NearAuthData = {
      ...baseAuthData,
      message: JSON.stringify(messageWithWrongTypes),
    };
    
    const tokenString = createAuthToken(authDataWithWrongTypes);

    await expect(verify(tokenString)).rejects.toThrow(
      "Invalid message structure: missing or invalid nonce, timestamp, or recipient"
    );
  });

  it("should handle timestamp too far in the past", async () => {
    const oldTimestamp = Date.now() - (25 * 60 * 60 * 1000); // 25 hours ago
    const oldMessageData: MessageData = {
      ...messageData,
      timestamp: oldTimestamp
    };
    
    const authDataWithOldTimestamp: NearAuthData = {
      ...baseAuthData,
      message: JSON.stringify(oldMessageData),
    };
    
    const tokenString = createAuthToken(authDataWithOldTimestamp);

    await expect(verify(tokenString)).rejects.toThrow(
      "Message timestamp too far from current time"
    );
  });

  it("should handle timestamp too far in the future", async () => {
    const futureTimestamp = Date.now() + (25 * 60 * 60 * 1000); // 25 hours in future
    const futureMessageData: MessageData = {
      ...messageData,
      timestamp: futureTimestamp
    };
    
    const authDataWithFutureTimestamp: NearAuthData = {
      ...baseAuthData,
      message: JSON.stringify(futureMessageData),
    };
    
    const tokenString = createAuthToken(authDataWithFutureTimestamp);

    await expect(verify(tokenString)).rejects.toThrow(
      "Message timestamp too far from current time"
    );
  });

  it("should handle nonce mismatch between message and auth data", async () => {
    const mismatchedMessageData: MessageData = {
      ...messageData,
      nonce: "different-nonce-base64-string-here-AAAA=" // Different from testNonce
    };
    
    const authDataWithMismatch: NearAuthData = {
      ...baseAuthData,
      message: JSON.stringify(mismatchedMessageData),
    };
    
    const tokenString = createAuthToken(authDataWithMismatch);

    await expect(verify(tokenString)).rejects.toThrow(
      "Nonce mismatch: message nonce vs signed payload nonce"
    );
  });

  it("should handle recipient mismatch between message and auth data", async () => {
    const mismatchedMessageData: MessageData = {
      ...messageData,
      recipient: "different-recipient.near"
    };
    
    const authDataWithMismatch: NearAuthData = {
      ...baseAuthData,
      message: JSON.stringify(mismatchedMessageData),
      // recipient in auth data remains "recipient.near"
    };
    
    const tokenString = createAuthToken(authDataWithMismatch);

    await expect(verify(tokenString)).rejects.toThrow(
      "Recipient mismatch: message recipient 'different-recipient.near' vs signed payload recipient 'recipient.near'"
    );
  });

  it("should handle FastNEAR API returning unexpected response format", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ unexpected: "format" }), // Missing account_ids array
    });

    const tokenString = createAuthToken(baseAuthData);

    await expect(verify(tokenString)).rejects.toThrow(
      "Public key ownership verification failed: API error or unexpected response"
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
      "Public key ownership verification failed: API error or unexpected response"
    );
  });

  it("should handle custom nonce validation throwing an error", async () => {
    const customValidateNonce = vi.fn().mockImplementation(() => {
      throw new Error("Custom validation error");
    });
    
    const tokenString = createAuthToken(baseAuthData);

    await expect(verify(tokenString, { 
      validateNonce: customValidateNonce 
    })).rejects.toThrow("Custom validation error");
  });

  it("should handle very long message data", async () => {
    const longData = "x".repeat(10000); // Very long string
    const longMessageData: MessageData = {
      ...messageData,
      data: longData
    };
    
    const authDataWithLongMessage: NearAuthData = {
      ...baseAuthData,
      message: JSON.stringify(longMessageData),
    };
    
    const tokenString = createAuthToken(authDataWithLongMessage);

    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [baseAuthData.account_id] }),
    });
    vi.spyOn(cryptoModule, "verifySignature").mockResolvedValue(true);

    const result = await verify(tokenString);
    expect(result.messageData.data).toBe(longData);
  });

  it("should handle message data with complex nested objects", async () => {
    const complexData = {
      user: {
        id: 123,
        profile: {
          name: "Test User",
          settings: {
            theme: "dark",
            notifications: true
          }
        }
      },
      actions: ["read", "write", "delete"],
      metadata: {
        version: "1.0",
        timestamp: Date.now()
      }
    };
    
    const complexMessageData: MessageData = {
      ...messageData,
      data: complexData
    };
    
    const authDataWithComplexMessage: NearAuthData = {
      ...baseAuthData,
      message: JSON.stringify(complexMessageData),
    };
    
    const tokenString = createAuthToken(authDataWithComplexMessage);

    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [baseAuthData.account_id] }),
    });
    vi.spyOn(cryptoModule, "verifySignature").mockResolvedValue(true);

    const result = await verify(tokenString);
    expect(result.messageData.data).toEqual(complexData);
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

  it("should handle .test.near accounts correctly", async () => {
    const testNearAccount = "myapp.test.near";
    const testNearMessageData: MessageData = {
      ...messageData,
      recipient: "test-recipient.near"
    };
    const testNearAuthData: NearAuthData = {
      ...baseAuthData,
      account_id: testNearAccount,
      message: JSON.stringify(testNearMessageData),
      recipient: "test-recipient.near"
    };
    
    const tokenString = createAuthToken(testNearAuthData);

    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [testNearAccount] }),
    });
    vi.spyOn(cryptoModule, "verifySignature").mockResolvedValue(true);

    const result = await verify(tokenString);
    
    expect(result.accountId).toBe(testNearAccount);
    expect(fetch).toHaveBeenCalledWith(
      `https://test.api.fastnear.com/v0/public_key/${testNearAuthData.public_key}`
    );
  });
});
