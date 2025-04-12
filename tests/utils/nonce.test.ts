import { describe, it, expect, vi } from 'vitest';
import { generateNonce, validateNonce } from '../../src/utils/nonce.js';

describe('Nonce Utilities', () => {
  describe('generateNonce', () => {
    it('should generate a nonce string', () => {
      const nonce = generateNonce();
      
      expect(typeof nonce).toBe('string');
      expect(nonce.length).toBeGreaterThan(0);
      
      // Should be a valid timestamp
      const timestamp = parseInt(nonce);
      expect(isNaN(timestamp)).toBe(false);
      
      // Should be close to current time
      const now = Date.now();
      expect(Math.abs(timestamp - now)).toBeLessThan(1000); // Within 1 second
    });
  });

  describe('validateNonce', () => {
    it('should validate a valid nonce', () => {
      const now = Date.now();
      const nonce = now.toString();
      
      const result = validateNonce(nonce);
      
      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it('should reject a nonce from the future', () => {
      const future = Date.now() + 10000; // 10 seconds in the future
      const nonce = future.toString();
      
      const result = validateNonce(nonce);
      
      expect(result.valid).toBe(false);
      expect(result.error).toBe('Nonce is in the future');
    });

    it('should reject a very old nonce', () => {
      // Mock Date.now to return a fixed value
      const realDateNow = Date.now;
      const mockNow = 1609459200000; // 2021-01-01
      global.Date.now = vi.fn(() => mockNow);
      
      // Create a nonce from 11 years ago
      const oldTimestamp = mockNow - (11 * 365 * 24 * 60 * 60 * 1000);
      const nonce = oldTimestamp.toString();
      
      const result = validateNonce(nonce);
      
      expect(result.valid).toBe(false);
      expect(result.error).toBe('Nonce is too old');
      
      // Restore original Date.now
      global.Date.now = realDateNow;
    });

    it('should reject an invalid nonce format', () => {
      const result = validateNonce('not-a-timestamp');
      
      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid nonce format');
    });
  });
});
