import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  ensureUint8Array,
  generateNonce,
  validateNonce,
} from "../../src/utils/nonce.js";

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

  describe("ensureUint8Array", () => {
    it("should return the same Uint8Array if it's already 32 bytes", () => {
      const original = new Uint8Array(32).fill(1); // Create a 32-byte array
      const result = ensureUint8Array(original);
      expect(result).toBe(original); // Should be the same object reference
    });

    it("should pad a shorter Uint8Array to 32 bytes", () => {
      const original = new Uint8Array([1, 2, 3]);
      const result = ensureUint8Array(original);
      expect(result).not.toBe(original); // Should be a new object
      expect(result.length).toBe(32);
      expect(result[0]).toBe(1);
      expect(result[1]).toBe(2);
      expect(result[2]).toBe(3);
      expect(result[3]).toBe(0); // Padding should be zeros
    });

    it("should convert string to Uint8Array", () => {
      const str = "test-string";
      const result = ensureUint8Array(str);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32); // Padded to 32 bytes

      const decoder = new TextDecoder();
      const decoded = decoder.decode(result);
      expect(decoded.startsWith(str)).toBe(true);
    });

    it("should convert number to Uint8Array", () => {
      const num = 12345;
      const result = ensureUint8Array(num);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32); // Padded to 32 bytes

      const decoder = new TextDecoder();
      const decoded = decoder.decode(result);
      expect(decoded.startsWith(num.toString())).toBe(true);
    });

    it("should convert Buffer to Uint8Array and pad to 32 bytes", () => {
      // Skip test if Buffer is not available (browser environment)
      if (typeof Buffer === "undefined") {
        return;
      }

      // Test with a short Buffer (less than 32 bytes)
      const shortBuffer = Buffer.from([1, 2, 3, 4, 5]);
      const shortResult = ensureUint8Array(shortBuffer);
      expect(shortResult).toBeInstanceOf(Uint8Array);
      expect(shortResult.length).toBe(32); // Should be padded to 32 bytes
      expect(shortResult[0]).toBe(1);
      expect(shortResult[4]).toBe(5);
      expect(shortResult[5]).toBe(0); // Padding should be zeros

      // Test with a Buffer exactly 32 bytes
      const exactBuffer = Buffer.alloc(32, 1); // All 1's
      const exactResult = ensureUint8Array(exactBuffer);
      expect(exactResult).toBeInstanceOf(Uint8Array);
      expect(exactResult.length).toBe(32);
      expect(exactResult[0]).toBe(1);
      expect(exactResult[31]).toBe(1);

      // Test with a Buffer longer than 32 bytes
      const longBuffer = Buffer.alloc(40, 2); // All 2's
      const longResult = ensureUint8Array(longBuffer);
      expect(longResult).toBeInstanceOf(Uint8Array);
      expect(longResult.length).toBe(32); // Should be truncated to 32 bytes
      expect(longResult[0]).toBe(2);
      expect(longResult[31]).toBe(2);
    });

    it("should throw for unsupported types", () => {
      expect(() => ensureUint8Array(null as any)).toThrow(
        "Unsupported nonce type",
      );
      expect(() => ensureUint8Array(undefined as any)).toThrow(
        "Unsupported nonce type",
      );
      expect(() => ensureUint8Array({} as any)).toThrow(
        "Unsupported nonce type",
      );
    });
  });
});
