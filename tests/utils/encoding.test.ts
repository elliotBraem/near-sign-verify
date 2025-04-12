import { describe, it, expect } from 'vitest';
import {
  stringToUint8Array,
  uint8ArrayToString,
  base64ToUint8Array,
  uint8ArrayToBase64,
} from '../../src/utils/encoding.js';

describe('Encoding Utilities', () => {
  describe('stringToUint8Array', () => {
    it('should convert a string to Uint8Array', () => {
      const str = 'Hello, world!';
      const result = stringToUint8Array(str);
      
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(str.length);
      expect(uint8ArrayToString(result)).toBe(str);
    });

    it('should handle empty strings', () => {
      const str = '';
      const result = stringToUint8Array(str);
      
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(0);
    });
  });

  describe('uint8ArrayToString', () => {
    it('should convert a Uint8Array to string', () => {
      const original = 'Hello, world!';
      const array = new TextEncoder().encode(original);
      const result = uint8ArrayToString(array);
      
      expect(result).toBe(original);
    });

    it('should handle empty arrays', () => {
      const array = new Uint8Array(0);
      const result = uint8ArrayToString(array);
      
      expect(result).toBe('');
    });
  });

  describe('base64ToUint8Array and uint8ArrayToBase64', () => {
    it('should convert between base64 and Uint8Array', () => {
      const original = 'Hello, world!';
      const array = stringToUint8Array(original);
      const base64 = uint8ArrayToBase64(array);
      const backToArray = base64ToUint8Array(base64);
      const backToString = uint8ArrayToString(backToArray);
      
      expect(backToString).toBe(original);
    });

    it('should handle empty values', () => {
      const emptyArray = new Uint8Array(0);
      const base64 = uint8ArrayToBase64(emptyArray);
      const backToArray = base64ToUint8Array(base64);
      
      expect(backToArray.length).toBe(0);
    });
  });
});
