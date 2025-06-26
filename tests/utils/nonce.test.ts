import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { generateNonce, validateNonce } from "../../src/utils/nonce.js";

describe("Nonce Utilities", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("generateNonce", () => {
    it("should generate a 32-byte nonce", () => {
      const nonce = generateNonce();
      expect(nonce).toBeInstanceOf(Uint8Array);
      expect(nonce.length).toBe(32);
    });

    it("should generate different nonces on subsequent calls", () => {
      const nonce1 = generateNonce();
      const nonce2 = generateNonce();
      expect(nonce1).not.toEqual(nonce2);
    });

    it("should include timestamp in the first 16 bytes", () => {
      const mockTime = 1234567890123;
      vi.spyOn(Date, "now").mockReturnValue(mockTime);

      const nonce = generateNonce();
      const decoder = new TextDecoder();
      const timestampBytes = nonce.slice(0, 16);
      const timestampStr = decoder.decode(timestampBytes).replace(/^0+/, "");
      const extractedTime = parseInt(timestampStr, 10);

      expect(extractedTime).toBe(mockTime);
    });
  });

  describe("validateNonce", () => {
    it("should validate a fresh nonce", () => {
      const nonce = generateNonce();

      expect(() => validateNonce(nonce)).not.toThrow();
    });

    it("should reject an expired nonce", () => {
      const oldTime = Date.now() - 2 * 60 * 60 * 1000; // 2 hours ago
      const oldTimeStr = oldTime.toString().padStart(16, "0");
      const encoder = new TextEncoder();
      const nonce = new Uint8Array(32);
      const timestampBytes = encoder.encode(oldTimeStr);
      nonce.set(timestampBytes.slice(0, 16), 0);

      expect(() => validateNonce(nonce, 60 * 60 * 1000)).toThrow("expired"); // 1 hour max age
    });

    it("should accept a nonce within maxAge", () => {
      const recentTime = Date.now() - 60 * 60 * 1000; // 1 hour ago
      const recentTimeStr = recentTime.toString().padStart(16, "0");
      const encoder = new TextEncoder();
      const nonce = new Uint8Array(32);
      const timestampBytes = encoder.encode(recentTimeStr);
      nonce.set(timestampBytes.slice(0, 16), 0);

      expect(() => validateNonce(nonce, 2 * 60 * 60 * 1000)).not.toThrow(); // 2 hour max age
    });

    it("should reject a nonce with invalid length", () => {
      const shortNonce = new Uint8Array(16); // Should be 32 bytes

      expect(() => validateNonce(shortNonce)).toThrow("Invalid nonce length");
    });

    it("should reject a nonce with invalid timestamp", () => {
      const nonce = new Uint8Array(32);
      // Fill with non-numeric characters
      const encoder = new TextEncoder();
      const invalidBytes = encoder.encode("abcdefghijklmnop");
      nonce.set(invalidBytes, 0);

      expect(() => validateNonce(nonce)).toThrow("Invalid timestamp in nonce");
    });

    it("should handle error cases gracefully", () => {
      const nonce = new Uint8Array(32);
      vi.spyOn(TextDecoder.prototype, "decode").mockImplementation(() => {
        throw new Error("Decoding error");
      });

      expect(() => validateNonce(nonce)).toThrow("Decoding error");
    });
  });
});
