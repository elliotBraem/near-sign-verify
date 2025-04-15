import { describe, it, expect, vi } from "vitest";
import { generateNonce, validateNonce } from "../../src/utils/nonce.js";

describe("Nonce Utilities", () => {
  describe("generateNonce", () => {
    it("should generate a 32-byte Uint8Array", () => {
      const nonce = generateNonce();

      expect(nonce).toBeInstanceOf(Uint8Array);
      expect(nonce.length).toBe(32);
    });

    it("should generate timestamp-based nonces", () => {
      const now = Date.now();
      vi.spyOn(Date, "now").mockImplementation(() => now);

      const nonce = generateNonce();
      const decoder = new TextDecoder();
      const timestampStr = decoder.decode(nonce).replace(/^0+/, "");
      const timestamp = parseInt(timestampStr, 10);

      expect(timestamp).toBe(now);

      vi.restoreAllMocks();
    });

    it("should generate unique nonces", () => {
      const nonce1 = generateNonce();
      const nonce2 = generateNonce();

      expect(nonce1).not.toEqual(nonce2);
    });
  });

  describe("validateNonce", () => {
    it("should validate a fresh nonce", () => {
      const nonce = generateNonce();
      const result = validateNonce(nonce);

      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it("should reject an expired nonce", () => {
      // Mock time to generate an old nonce
      const oldTime = Date.now() - 25 * 60 * 60 * 1000; // 25 hours ago
      vi.spyOn(Date, "now").mockImplementation(() => oldTime);
      const oldNonce = generateNonce();
      vi.restoreAllMocks();

      const result = validateNonce(oldNonce);

      expect(result.valid).toBe(false);
      expect(result.error).toBe("Nonce has expired");
    });

    it("should accept a nonce within maxAge", () => {
      // Mock time to generate a nonce 1 hour ago
      const oneHourAgo = Date.now() - 1 * 60 * 60 * 1000;
      vi.spyOn(Date, "now").mockImplementation(() => oneHourAgo);
      const nonce = generateNonce();
      vi.restoreAllMocks();

      const result = validateNonce(nonce, 2 * 60 * 60 * 1000); // 2 hour max age

      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it("should reject a nonce with invalid length", () => {
      const invalidNonce = new Uint8Array(16); // Wrong length
      const result = validateNonce(invalidNonce);

      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid nonce length");
    });

    it("should reject a nonce with invalid timestamp", () => {
      const invalidNonce = new Uint8Array(32);
      invalidNonce.fill(65); // Fill with 'A' characters
      const result = validateNonce(invalidNonce);

      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid timestamp in nonce");
    });

    it("should handle error cases gracefully", () => {
      const nonce = new Uint8Array(32);
      vi.spyOn(TextDecoder.prototype, "decode").mockImplementation(() => {
        throw new Error("Decoding error");
      });

      const result = validateNonce(nonce);

      expect(result.valid).toBe(false);
      expect(result.error).toBe("Decoding error");

      vi.restoreAllMocks();
    });
  });
});
