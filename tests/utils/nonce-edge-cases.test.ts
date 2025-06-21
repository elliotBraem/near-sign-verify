import { afterEach, describe, expect, it, vi } from "vitest";
import { generateNonce, validateNonce } from "../../src/utils/nonce.js";
import { describe, expect, it, vi, afterEach } from "vitest";

describe("nonce - Edge Cases", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should handle nonce validation with exactly max age", () => {
    const maxAge = 5 * 60 * 1000; // 5 minutes
    const currentTime = 1000000000000; // Fixed timestamp

    // Mock Date.now to return fixed time
    vi.spyOn(Date, "now").mockReturnValue(currentTime);

    // Create nonce that is exactly maxAge old
    const oldTime = currentTime - maxAge;
    const oldTimeStr = oldTime.toString().padStart(16, "0");
    const encoder = new TextEncoder();
    const oldNonce = new Uint8Array(32);
    const timestampBytes = encoder.encode(oldTimeStr);
    oldNonce.set(timestampBytes.slice(0, 16), 0);

    // Should not throw when exactly at the boundary
    expect(() => validateNonce(oldNonce, maxAge)).not.toThrow();
  });

  it("should handle nonce validation with time slightly over max age", () => {
    const maxAge = 5 * 60 * 1000; // 5 minutes
    const currentTime = 1000000000000; // Fixed timestamp

    // Mock Date.now to return fixed time
    vi.spyOn(Date, "now").mockReturnValue(currentTime);

    // Create nonce that is slightly over maxAge old
    const oldTime = currentTime - maxAge - 1; // 1ms over the limit
    const oldTimeStr = oldTime.toString().padStart(16, "0");
    const encoder = new TextEncoder();
    const oldNonce = new Uint8Array(32);
    const timestampBytes = encoder.encode(oldTimeStr);
    oldNonce.set(timestampBytes.slice(0, 16), 0);

    expect(() => validateNonce(oldNonce, maxAge)).toThrow("expired");
  });

  it("should handle future nonce timestamps", () => {
    const currentTime = 1000000000000;
    vi.spyOn(Date, "now").mockReturnValue(currentTime);

    // Create nonce with future timestamp
    const futureTime = currentTime + 60000; // 1 minute in future
    const futureTimeStr = futureTime.toString().padStart(16, "0");
    const encoder = new TextEncoder();
    const futureNonce = new Uint8Array(32);
    const timestampBytes = encoder.encode(futureTimeStr);
    futureNonce.set(timestampBytes.slice(0, 16), 0);

    expect(() => validateNonce(futureNonce, 5 * 60 * 1000)).toThrow("future");
  });

  it("should handle nonce with invalid length", () => {
    const shortNonce = new Uint8Array(16); // Should be 32 bytes

    expect(() => validateNonce(shortNonce)).toThrow("Invalid nonce length");
  });

  it("should handle nonce with zero timestamp", () => {
    const zeroNonce = new Uint8Array(32); // All zeros, including timestamp

    expect(() => validateNonce(zeroNonce)).toThrow(
      "Invalid timestamp in nonce",
    );
  });

  it("should handle very large timestamp values", () => {
    const currentTime = Date.now();
    vi.spyOn(Date, "now").mockReturnValue(currentTime);

    // Create nonce with maximum safe integer timestamp
    const maxTime = Number.MAX_SAFE_INTEGER;
    const maxTimeStr = maxTime.toString().padStart(16, "0");
    const encoder = new TextEncoder();
    const maxNonce = new Uint8Array(32);
    const timestampBytes = encoder.encode(maxTimeStr);
    maxNonce.set(timestampBytes.slice(0, 16), 0);

    expect(() => validateNonce(maxNonce)).toThrow("future");
  });

  it("should generate nonce with current timestamp", () => {
    const currentTime = 1000000000000;
    vi.spyOn(Date, "now").mockReturnValue(currentTime);

    const nonce = generateNonce();

    expect(nonce).toBeInstanceOf(Uint8Array);
    expect(nonce.length).toBe(32);

    // Extract timestamp from first 16 bytes
    const decoder = new TextDecoder();
    const timestampBytes = nonce.slice(0, 16);
    const timestampStr = decoder.decode(timestampBytes).replace(/^0+/, "");
    const extractedTime = parseInt(timestampStr, 10);

    expect(extractedTime).toBe(currentTime);
  });

  it("should generate different random bytes for each nonce", () => {
    const nonce1 = generateNonce();
    const nonce2 = generateNonce();

    // Timestamps might be the same (first 16 bytes), but random bytes should differ
    const randomBytes1 = nonce1.slice(16);
    const randomBytes2 = nonce2.slice(16);

    expect(randomBytes1).not.toEqual(randomBytes2);
  });

  it("should handle default max age when not provided", () => {
    const currentTime = Date.now();

    // Create nonce that is 25 hours old (exceeds default 24h)
    const oldTime = currentTime - 25 * 60 * 60 * 1000;
    const oldTimeStr = oldTime.toString().padStart(16, "0");
    const encoder = new TextEncoder();
    const oldNonce = new Uint8Array(32);
    const timestampBytes = encoder.encode(oldTimeStr);
    oldNonce.set(timestampBytes.slice(0, 16), 0);

    expect(() => validateNonce(oldNonce)).toThrow("expired");
  });

  it("should handle nonce validation with zero max age", () => {
    const currentTime = Date.now();
    vi.spyOn(Date, "now").mockReturnValue(currentTime);

    // Create nonce with current timestamp
    const currentTimeStr = currentTime.toString().padStart(16, "0");
    const encoder = new TextEncoder();
    const currentNonce = new Uint8Array(32);
    const timestampBytes = encoder.encode(currentTimeStr);
    currentNonce.set(timestampBytes.slice(0, 16), 0);

    // Should not throw when exactly at current time with zero max age
    expect(() => validateNonce(currentNonce, 0)).not.toThrow();
  });

  it("should handle nonce with non-numeric timestamp", () => {
    // Create nonce with non-numeric data in timestamp area
    const encoder = new TextEncoder();
    const invalidNonce = new Uint8Array(32);
    const invalidBytes = encoder.encode("abcdefghijklmnop"); // 16 non-numeric chars
    invalidNonce.set(invalidBytes, 0);

    expect(() => validateNonce(invalidNonce)).toThrow(
      "Invalid timestamp in nonce",
    );
  });

  describe("ensureUint8Array - Edge Cases", () => {
    it("should handle empty string", () => {
      const result = ensureUint8Array("");
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32); // Padded to 32 bytes
    });

    it("should handle zero as number", () => {
      const result = ensureUint8Array(0);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32); // Padded to 32 bytes

      const decoder = new TextDecoder();
      const decoded = decoder.decode(result);
      expect(decoded.startsWith("0")).toBe(true);
    });

    it("should handle very large numbers", () => {
      const largeNum = Number.MAX_SAFE_INTEGER;
      const result = ensureUint8Array(largeNum);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32); // Padded to 32 bytes

      const decoder = new TextDecoder();
      const decoded = decoder.decode(result);
      expect(decoded.startsWith(largeNum.toString())).toBe(true);
    });

    it("should handle unicode strings", () => {
      const unicodeStr = "测试字符串";
      const result = ensureUint8Array(unicodeStr);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32); // Padded to 32 bytes

      const decoder = new TextDecoder();
      const decoded = decoder.decode(result);
      expect(decoded.startsWith(unicodeStr)).toBe(true);
    });

    it("should handle special characters", () => {
      const specialChars = "!@#$%^&*()_+{}|:<>?~`-=[]\\;',./";
      const result = ensureUint8Array(specialChars);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32); // Padded to 32 bytes

      const decoder = new TextDecoder();
      const decoded = decoder.decode(result);
      expect(decoded.startsWith(specialChars)).toBe(true);
    });
  });
});
