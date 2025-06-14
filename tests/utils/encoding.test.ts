import { describe, expect, it } from "vitest";
import {
  stringToUint8Array,
  uint8ArrayToString,
} from "../../src/utils/encoding.js";

describe("Encoding Utilities", () => {
  describe("stringToUint8Array", () => {
    it("should convert a string to Uint8Array", () => {
      const str = "Hello, world!";
      const result = stringToUint8Array(str);

      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(str.length);
      expect(uint8ArrayToString(result)).toBe(str);
    });

    it("should handle empty strings", () => {
      const str = "";
      const result = stringToUint8Array(str);

      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(0);
    });
  });

  describe("uint8ArrayToString", () => {
    it("should convert a Uint8Array to string", () => {
      const original = "Hello, world!";
      const array = new TextEncoder().encode(original);
      const result = uint8ArrayToString(array);

      expect(result).toBe(original);
    });

    it("should handle empty arrays", () => {
      const array = new Uint8Array(0);
      const result = uint8ArrayToString(array);

      expect(result).toBe("");
    });
  });
});
