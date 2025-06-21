import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createAuthToken } from "../../src/auth/createAuthToken.js";
import { verify } from "../../src/auth/verify.js";
import * as cryptoModule from "../../src/crypto/crypto.js";
import type { NearAuthData } from "../../src/schemas.js";
import type { NonceType } from "../../src/types.js";
import * as nonceModule from "../../src/utils/nonce.js";

// Mock dependencies
vi.mock("../../src/crypto/crypto.js");
vi.mock("../../src/utils/nonce.js");

// Mock global fetch
global.fetch = vi.fn();

describe("verify - Edge Cases", () => {
  const testNonce = new Uint8Array(32);

  const baseAuthData: NearAuthData = {
    accountId: "testuser.testnet",
    publicKey: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
    signature:
      "YN7xw5bhbD2VzrOlyyGwKKEaCBsuCVO9vu1AY1GkqQRRfOL2JNTjUUxJXp9KfC2nmA2xvytDdUzel0vmr/VDuA==",
    message: "test message",
    nonce: Array.from(testNonce),
    recipient: "recipient.near",
    callbackUrl: null,
    state: "edge-case-state",
  };

  beforeEach(() => {
    vi.resetAllMocks();
    // Default successful nonce validation (no throw = success)
    vi.spyOn(nonceModule, "validateNonce").mockImplementation(() => {});
    vi.spyOn(nonceModule, "ensureUint8Array").mockImplementation((nonce) => {
      if (nonce instanceof Uint8Array) {
        return nonce;
      }
      return new Uint8Array(baseAuthData.nonce);
    });
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
      json: async () => ({ unexpected: "format" }), // Missing accountIds array
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
      json: async () => ({ account_ids: [baseAuthData.accountId] }),
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
      json: async () => ({ account_ids: [baseAuthData.accountId] }),
    });
    vi.spyOn(cryptoModule, "verifySignature").mockResolvedValue(true);

    const result = await verify(tokenString);
    expect(result.message).toEqual(JSON.stringify(complexData));
  });

  it("should handle account ID with special characters", async () => {
    const specialAccountId = "test-user_123.testnet";
    const specialAuthData: NearAuthData = {
      ...baseAuthData,
      accountId: specialAccountId,
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

  it("should handle custom state validation throwing an error", async () => {
    const customValidateState = vi.fn().mockImplementation(() => {
      throw new Error("Custom state validation error");
    });
    const tokenString = createAuthToken(baseAuthData);
    await expect(
      verify(tokenString, {
        validateState: customValidateState,
      }),
    ).rejects.toThrow("Custom state validation error");
    expect(customValidateState).toHaveBeenCalledWith("edge-case-state");
  });

  it("should handle null state in token when expectedState is provided", async () => {
    const authDataWithNullState: NearAuthData = {
      ...baseAuthData,
      state: null,
    };
    const tokenString = createAuthToken(authDataWithNullState);
    await expect(
      verify(tokenString, {
        expectedState: "some-state",
      }),
    ).rejects.toThrow("State mismatch: expected 'some-state', got 'undefined'");
  });

  it("should pass null state from token to custom validateState function", async () => {
    const authDataWithNullState: NearAuthData = {
      ...baseAuthData,
      state: null,
    };
    const tokenString = createAuthToken(authDataWithNullState);
    const customValidateState = vi.fn().mockReturnValue(false);

    await expect(
      verify(tokenString, {
        validateState: customValidateState,
      }),
    ).rejects.toThrow("Custom state validation failed");
    expect(customValidateState).toHaveBeenCalledWith(null);
  });

  it("should pass undefined state from token to custom validateState function", async () => {
    const authDataWithoutStateProperty: NearAuthData = {
      ...baseAuthData,
      state: null,
    };
    const tokenString = createAuthToken(authDataWithoutStateProperty);
    const customValidateState = vi.fn().mockReturnValue(true); // Mock to pass validation to check call

    // Mock other checks to isolate state validation
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        account_ids: [authDataWithoutStateProperty.accountId],
      }),
    });
    vi.spyOn(cryptoModule, "verifySignature").mockResolvedValue(true);

    await verify(tokenString, {
      validateState: customValidateState,
    });
    expect(customValidateState).toHaveBeenCalledWith(null);
  });

  it("should succeed if expectedState is undefined and token state is undefined", async () => {
    const authDataUndefinedState: NearAuthData = {
      ...baseAuthData,
      state: null,
    };
    const tokenString = createAuthToken(authDataUndefinedState);
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [authDataUndefinedState.accountId] }),
    });
    vi.spyOn(cryptoModule, "verifySignature").mockResolvedValue(true);

    const result = await verify(tokenString, { expectedState: undefined });
    expect(result.state).toBeUndefined();
  });

  it("should handle custom message validation throwing an error", async () => {
    const customValidateMessage = vi.fn().mockImplementation(() => {
      throw new Error("Custom message validation error");
    });
    const tokenString = createAuthToken(baseAuthData);
    await expect(
      verify(tokenString, {
        validateMessage: customValidateMessage,
      }),
    ).rejects.toThrow("Custom message validation error");
    expect(customValidateMessage).toHaveBeenCalledWith(baseAuthData.message);
  });

  it("should succeed with empty string message if expectedMessage is also an empty string", async () => {
    const authDataEmptyMessage: NearAuthData = {
      ...baseAuthData,
      message: "",
    };
    const tokenString = createAuthToken(authDataEmptyMessage);
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [authDataEmptyMessage.accountId] }),
    });
    vi.spyOn(cryptoModule, "verifySignature").mockResolvedValue(true);

    const result = await verify(tokenString, { expectedMessage: "" });
    expect(result.message).toBe("");
  });

  it("should reject if expectedMessage is an empty string but token message is not", async () => {
    const tokenString = createAuthToken(baseAuthData); // baseAuthData.message is "test message"
    await expect(
      verify(tokenString, {
        expectedMessage: "",
      }),
    ).rejects.toThrow("Message mismatch: expected '', got 'test message'");
  });

  it("should pass empty string message to custom validateMessage function", async () => {
    const authDataEmptyMessage: NearAuthData = {
      ...baseAuthData,
      message: "",
    };
    const tokenString = createAuthToken(authDataEmptyMessage);
    const customValidateMessage = vi.fn().mockReturnValue(true);
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [authDataEmptyMessage.accountId] }),
    });
    vi.spyOn(cryptoModule, "verifySignature").mockResolvedValue(true);

    await verify(tokenString, {
      validateMessage: customValidateMessage,
    });
    expect(customValidateMessage).toHaveBeenCalledWith("");
  });

  it("should handle extreme nonce types with custom validation", async () => {
    const tokenString = createAuthToken(baseAuthData);

    // Test with extremely large number
    const largeNumberValidation = vi.fn().mockReturnValue(true);
    vi.spyOn(nonceModule, "ensureUint8Array").mockImplementation(
      (nonce: NonceType) => {
        return new Uint8Array(32);
      },
    );

    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [baseAuthData.accountId] }),
    });
    vi.spyOn(cryptoModule, "verifySignature").mockResolvedValue(true);

    await verify<number>(tokenString, {
      validateNonce: largeNumberValidation,
    });
    expect(largeNumberValidation).toHaveBeenCalled();

    // Test with very long string
    const longStringValidation = vi.fn().mockReturnValue(true);
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [baseAuthData.accountId] }),
    });

    await verify<string>(tokenString, {
      validateNonce: longStringValidation,
    });
    expect(longStringValidation).toHaveBeenCalled();
  });
});
