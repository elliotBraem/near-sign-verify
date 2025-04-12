import { describe, it, expect } from "vitest";
import { generateNonce, validateNonce } from "../../src/utils/nonce.js";

describe("Nonce Utilities", () => {
  describe("generateNonce", () => {
    it("should generate a base64 encoded nonce string", () => {
      const nonce = generateNonce();

      expect(typeof nonce).toBe("string");
      expect(nonce.length).toBeGreaterThan(0);

      // Should be a valid base64 string
      expect(nonce).toMatch(/^[A-Za-z0-9+/=]+$/);
    });

    it("should generate unique nonces", () => {
      const nonce1 = generateNonce();
      const nonce2 = generateNonce();

      expect(nonce1).not.toBe(nonce2);
    });
  });

  describe("validateNonce", () => {
    it("should validate a valid nonce", () => {
      // Generate a valid nonce
      const nonce = generateNonce();

      const result = validateNonce(nonce);

      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it("should reject an invalid nonce format", () => {
      const result = validateNonce("not-a-valid-base64!");

      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid nonce format");
    });

    it("should handle empty nonce", () => {
      const result = validateNonce("");

      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid nonce format");
    });

    it("should handle error cases gracefully", () => {
      // Mock a scenario that would cause an error
      const originalRegExpTest = RegExp.prototype.test;
      RegExp.prototype.test = () => {
        throw new Error("Test error");
      };

      const result = validateNonce("any-value");

      expect(result.valid).toBe(false);
      expect(result.error).toBe("Test error");

      // Restore original function
      RegExp.prototype.test = originalRegExpTest;
    });
  });
});
