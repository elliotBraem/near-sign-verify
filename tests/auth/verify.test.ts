import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { verify } from "../../src/auth/verify.js";
import * as cryptoModule from "../../src/crypto/crypto.js";
import * as nonceModule from "../../src/utils/nonce.js";
import type { NearAuthData } from "../../src/types.js";

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
    signature: "base64signature",
    message: "Hello, world!",
    nonce: testNonce,
    recipient: "recipient.near",
  };

  beforeEach(() => {
    vi.resetAllMocks();
    // Default successful nonce validation for most tests
    vi.spyOn(nonceModule, "validateNonce").mockReturnValue({ valid: true });
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

    const result = await verify(baseAuthData);

    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
    expect(nonceModule.validateNonce).toHaveBeenCalledWith(
      baseAuthData.nonce,
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

    const result = await verify(baseAuthData);

    expect(result.valid).toBe(false);
    expect(result.error).toBe(
      "Public key does not belong to the specified account or does not meet access requirements.",
    );
    expect(cryptoModule.verifySignature).not.toHaveBeenCalled();
  });

  it("should reject if FastNEAR API request fails (network error)", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("Network failure"),
    );

    const result = await verify(baseAuthData);

    expect(result.valid).toBe(false);
    expect(result.error).toBe(
      "Failed to verify public key ownership with external API.",
    );
    expect(cryptoModule.verifySignature).not.toHaveBeenCalled();
  });

  it("should reject if FastNEAR API returns a non-ok response", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
    });

    const result = await verify(baseAuthData);

    expect(result.valid).toBe(false);
    expect(result.error).toBe(
      "Failed to verify public key ownership with external API.",
    );
    expect(cryptoModule.verifySignature).not.toHaveBeenCalled();
  });

  it("should use /all endpoint and succeed if requireFullAccessKey is false", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [baseAuthData.account_id] }),
    });
    vi.spyOn(cryptoModule, "verifySignature").mockResolvedValue(true);

    const result = await verify(baseAuthData, { requireFullAccessKey: false });

    expect(result.valid).toBe(true);
    expect(fetch).toHaveBeenCalledWith(
      `https://test.api.fastnear.com/v0/public_key/${baseAuthData.public_key}/all`,
    );
  });

  it("should use mainnet FastNEAR API for mainnet accounts", async () => {
    const mainnetAuthData: NearAuthData = {
      ...baseAuthData,
      account_id: "user.near",
    };
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [mainnetAuthData.account_id] }),
    });
    vi.spyOn(cryptoModule, "verifySignature").mockResolvedValue(true);

    const result = await verify(mainnetAuthData);

    expect(result.valid).toBe(true);
    expect(fetch).toHaveBeenCalledWith(
      `https://api.fastnear.com/v0/public_key/${mainnetAuthData.public_key}`,
    );
  });

  it("should reject an invalid cryptographic signature after successful ownership check", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [baseAuthData.account_id] }),
    });
    vi.spyOn(cryptoModule, "verifySignature").mockResolvedValue(false); // Crypto sig fails

    const result = await verify(baseAuthData);

    expect(result.valid).toBe(false);
    expect(result.error).toBe("Invalid signature");
  });

  it("should reject if nonce validation fails", async () => {
    vi.spyOn(nonceModule, "validateNonce").mockReturnValue({
      valid: false,
      error: "Nonce expired",
    });

    const result = await verify(baseAuthData);

    expect(result.valid).toBe(false);
    expect(result.error).toBe("Nonce expired");
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

    const result = await verify(baseAuthData);

    expect(result.valid).toBe(false);
    expect(result.error).toBe("Crypto error");
  });

  it("should pass nonceMaxAge to validateNonce if provided", async () => {
    const nonceMaxAge = 5 * 60 * 1000; // 5 minutes
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [baseAuthData.account_id] }),
    });
    vi.spyOn(cryptoModule, "verifySignature").mockResolvedValue(true);

    const result = await verify(baseAuthData, { nonceMaxAge });

    expect(result.valid).toBe(true);
    expect(nonceModule.validateNonce).toHaveBeenCalledWith(
      baseAuthData.nonce,
      nonceMaxAge,
    );
  });

  it("should handle unexpected error during public key decoding", async () => {
    // This test assumes nonce validation and public key ownership check pass,
    // but an error occurs during bs58.decode or base64ToUint8Array.
    // We can simulate this by making bs58.decode throw an error.
    // For simplicity, we'll let the error propagate from the main try-catch.
    // This requires not mocking bs58 or base64ToUint8Array directly,
    // but ensuring the path to an error in that section.
    // A more direct way would be to mock those specific utils if they were separate.
    // Here, we'll make publicKey invalid to cause bs58.decode to fail.

    const faultyAuthData: NearAuthData = {
      ...baseAuthData,
      public_key: "ed25519:InvalidKeyChars$$", // Invalid base58 characters
    };

    (fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ account_ids: [faultyAuthData.account_id] }),
    });
    // validateNonce is already mocked to return true.

    const result = await verify(faultyAuthData);
    expect(result.valid).toBe(false);
    // The error message from bs58.decode might vary, so check it's an error.
    expect(result.error).toEqual(expect.any(String));
    // Check it's not one of the specific errors we've defined.
    expect(result.error).not.toBe("Invalid signature");
    expect(result.error).not.toBe(
      "Public key does not belong to the specified account or does not meet access requirements.",
    );
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

    const result = await verify(baseAuthData);
    expect(result.valid).toBe(false);
    expect(result.error).toBe(
      "Failed to verify public key ownership with external API.",
    );
  });
});
