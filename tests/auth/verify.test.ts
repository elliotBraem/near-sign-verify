import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createAuthToken } from "../../src/auth/createAuthToken.js";
import { verify } from "../../src/auth/verify.js";
import * as cryptoModule from "../../src/crypto/crypto.js";
import type { NearAuthData } from "../../src/schemas.js";
import * as nonceModule from "../../src/utils/nonce.js";

// Mock dependencies
vi.mock("../../src/crypto/crypto.js");
vi.mock("../../src/utils/nonce.js");

// Mock global fetch
global.fetch = vi.fn();

describe("verify", () => {
  const testNonce = new Uint8Array(32); // Assuming a valid 32-byte nonce

  const baseAuthData: NearAuthData = {
    account_id: "testuser.testnet",
    public_key: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
    signature: "YN7xw5bhbD2VzrOlyyGwKKEaCBsuCVO9vu1AY1GkqQRRfOL2JNTjUUxJXp9KfC2nmA2xvytDdUzel0vmr/VDuA==",
    message: "test message",
    nonce: Array.from(testNonce),
    recipient: "recipient.near",
    callback_url: null,
  };

  let authTokenString: string;

  beforeEach(() => {
    vi.resetAllMocks();
    // Default successful nonce validation for most tests (no throw = success)
    vi.spyOn(nonceModule, "validateNonce").mockImplementation(() => {});
    // Create the auth token string for tests
    authTokenString = createAuthToken(baseAuthData);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("should validate a signature with valid nonce, ownership, and crypto signature", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [baseAuthData.account_id] }),
    });
    vi.spyOn(cryptoModule, "verifySignature").mockResolvedValue(true);

    const result = await verify(authTokenString);

    expect(result.accountId).toBe(baseAuthData.account_id);
    expect(result.publicKey).toBe(baseAuthData.public_key);
    expect(result.message).toEqual("test message");
    expect(nonceModule.validateNonce).toHaveBeenCalledWith(
      new Uint8Array(baseAuthData.nonce),
      undefined,
    ); // No nonceMaxAge passed
    expect(fetch).toHaveBeenCalledWith(
      `https://test.api.fastnear.com/v0/public_key/${baseAuthData.public_key}`, // Default requireFullAccessKey=true
    );
    expect(cryptoModule.verifySignature).toHaveBeenCalled();
  });

  it("should reject if public key does not belong to the account", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: ["anotheruser.testnet"] }), // account_id not in list
    });

    await expect(verify(authTokenString)).rejects.toThrow(
      "Public key ownership verification failed",
    );
    expect(cryptoModule.verifySignature).not.toHaveBeenCalled();
  });

  it("should reject if FastNEAR API request fails (network error)", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("Network failure"),
    );

    await expect(verify(authTokenString)).rejects.toThrow(
      "Public key ownership verification failed",
    );
    expect(cryptoModule.verifySignature).not.toHaveBeenCalled();
  });

  it("should reject if FastNEAR API returns a non-ok response", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
    });

    await expect(verify(authTokenString)).rejects.toThrow(
      "Public key ownership verification failed",
    );
    expect(cryptoModule.verifySignature).not.toHaveBeenCalled();
  });

  it("should use /all endpoint and succeed if requireFullAccessKey is false", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [baseAuthData.account_id] }),
    });
    vi.spyOn(cryptoModule, "verifySignature").mockResolvedValue(true);

    const result = await verify(authTokenString, {
      requireFullAccessKey: false,
    });

    expect(result.accountId).toBe(baseAuthData.account_id);
    expect(fetch).toHaveBeenCalledWith(
      `https://test.api.fastnear.com/v0/public_key/${baseAuthData.public_key}/all`,
    );
  });

  it("should use mainnet FastNEAR API for mainnet accounts", async () => {
    const mainnetAuthData: NearAuthData = {
      ...baseAuthData,
      account_id: "user.near",
      message: "test message",
      recipient: "mainnet-recipient.near",
    };
    const mainnetTokenString = createAuthToken(mainnetAuthData);

    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [mainnetAuthData.account_id] }),
    });
    vi.spyOn(cryptoModule, "verifySignature").mockResolvedValue(true);

    const result = await verify(mainnetTokenString);

    expect(result.accountId).toBe(mainnetAuthData.account_id);
    expect(fetch).toHaveBeenCalledWith(
      `https://api.fastnear.com/v0/public_key/${mainnetAuthData.public_key}`,
    );
  });

  it("should reject an invalid cryptographic signature after successful ownership check", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [baseAuthData.account_id] }),
    });
    // Simulate crypto.verifySignature throwing an error for an invalid signature
    vi.spyOn(cryptoModule, "verifySignature").mockRejectedValue(
      new Error("Underlying crypto lib signature check failed"),
    );

    await expect(verify(authTokenString)).rejects.toThrow();
  });

  it("should reject if nonce validation fails", async () => {
    vi.spyOn(nonceModule, "validateNonce").mockImplementation(() => {
      throw new Error("Nonce expired");
    });

    await expect(verify(authTokenString)).rejects.toThrow(
      "Nonce validation failed: Nonce expired",
    );
    expect(fetch).not.toHaveBeenCalled();
    expect(cryptoModule.verifySignature).not.toHaveBeenCalled();
  });

  it("should handle exceptions during cryptographic signature validation", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [baseAuthData.account_id] }),
    });
    vi.spyOn(cryptoModule, "verifySignature").mockRejectedValue(
      new Error("Crypto error"),
    );

    await expect(verify(authTokenString)).rejects.toThrow();
  });

  it("should pass nonceMaxAge to validateNonce if provided", async () => {
    const nonceMaxAge = 5 * 60 * 1000; // 5 minutes
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [baseAuthData.account_id] }),
    });
    vi.spyOn(cryptoModule, "verifySignature").mockResolvedValue(true);

    const result = await verify(authTokenString, { nonceMaxAge });

    expect(result.accountId).toBe(baseAuthData.account_id);
    expect(nonceModule.validateNonce).toHaveBeenCalledWith(
      new Uint8Array(baseAuthData.nonce),
      nonceMaxAge,
    );
  });

  it("should handle unexpected error during public key decoding", async () => {
    const faultyAuthData: NearAuthData = {
      ...baseAuthData,
      public_key: "ed25519:InvalidKeyChars$$", // Invalid base58 characters
      message: JSON.stringify("faultyMessageData"),
    };
    const faultyTokenString = createAuthToken(faultyAuthData);

    // Mock fetch to make verifyPublicKeyOwner pass, so we can test PublicKey.fromString failure
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [faultyAuthData.account_id] }),
    });

    // The error should come from crypto.verifySignature when PublicKey.fromString fails.
    vi.spyOn(cryptoModule, "verifySignature").mockImplementation(
      async (hash, sig, pkString) => {
        if (pkString === faultyAuthData.public_key) {
          // Use the actual faulty public key
          // Simulate PublicKey.fromString throwing an error due to invalid characters
          throw new Error(
            `Failed to parse public key "${pkString}": BS58_DECODE_FAILURE`,
          );
        }
        // Fallback for any other call, though not expected in this specific test
        throw new Error(
          "verifySignature mock called with unexpected arguments in this test",
        );
      },
    );

    await expect(verify(faultyTokenString)).rejects.toThrow();
  });

  it("should return API failure when FastNEAR returns a non-ok response like 'Invalid argument'", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: false,
      status: 400,
      statusText: "Bad Request",
      text: async () => "Invalid argument.",
      json: async () => {
        throw new Error("Should not attempt to parse JSON");
      },
    });

    await expect(verify(authTokenString)).rejects.toThrow(
      "Public key ownership verification failed",
    );
  });

  it("should validate custom nonce validation function", async () => {
    const customValidateNonce = vi.fn().mockReturnValue(false);

    await expect(
      verify(authTokenString, {
        validateNonce: customValidateNonce,
      }),
    ).rejects.toThrow("Custom nonce validation failed");

    expect(customValidateNonce).toHaveBeenCalledWith(new Uint8Array(32));
    expect(fetch).not.toHaveBeenCalled();
  });

  it("should validate expectedRecipient option", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [baseAuthData.account_id] }),
    });

    await expect(
      verify(authTokenString, {
        expectedRecipient: "different-recipient.near",
      }),
    ).rejects.toThrow(
      "Recipient mismatch: expected 'different-recipient.near'",
    );

    expect(fetch).not.toHaveBeenCalled();
  });
});
