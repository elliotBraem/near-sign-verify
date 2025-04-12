import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { validateSignature } from '../../src/auth/validateSignature.js';
import * as cryptoModule from '../../src/crypto/crypto.js';
import * as nonceModule from '../../src/utils/nonce.js';

// Mock the crypto and nonce modules
vi.mock('../../src/crypto/crypto.js');
vi.mock('../../src/utils/nonce.js');

describe('validateSignature', () => {
  beforeEach(() => {
    // Reset mocks before each test
    vi.resetAllMocks();
  });

  afterEach(() => {
    // Clear mocks after each test
    vi.clearAllMocks();
  });

  it('should validate a valid signature', async () => {
    // Mock the validateNonce function to return valid
    vi.spyOn(nonceModule, 'validateNonce').mockReturnValue({ valid: true });
    
    // Mock the verifySignature function to return true
    vi.spyOn(cryptoModule, 'verifySignature').mockResolvedValue(true);
    
    // Mock other necessary functions
    vi.spyOn(cryptoModule, 'padNonce').mockReturnValue(new Uint8Array(32));
    
    const result = await validateSignature({
      signature: 'base64signature',
      message: 'Hello, world!',
      publicKey: 'ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T',
      nonce: '1609459200000',
      recipient: 'api.example.com',
    });
    
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
    
    // Verify that the functions were called with the correct arguments
    expect(nonceModule.validateNonce).toHaveBeenCalledWith('1609459200000');
    expect(cryptoModule.padNonce).toHaveBeenCalledWith('1609459200000');
    expect(cryptoModule.verifySignature).toHaveBeenCalled();
  });

  it('should reject an invalid signature', async () => {
    // Mock the validateNonce function to return valid
    vi.spyOn(nonceModule, 'validateNonce').mockReturnValue({ valid: true });
    
    // Mock the verifySignature function to return false
    vi.spyOn(cryptoModule, 'verifySignature').mockResolvedValue(false);
    
    // Mock other necessary functions
    vi.spyOn(cryptoModule, 'padNonce').mockReturnValue(new Uint8Array(32));
    
    const result = await validateSignature({
      signature: 'invalidsignature',
      message: 'Hello, world!',
      publicKey: 'ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T',
      nonce: '1609459200000',
      recipient: 'api.example.com',
    });
    
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Invalid signature');
  });

  it('should reject if nonce validation fails', async () => {
    // Mock the validateNonce function to return invalid
    vi.spyOn(nonceModule, 'validateNonce').mockReturnValue({
      valid: false,
      error: 'Invalid nonce',
    });
    
    const result = await validateSignature({
      signature: 'base64signature',
      message: 'Hello, world!',
      publicKey: 'ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T',
      nonce: 'invalid-nonce',
      recipient: 'api.example.com',
    });
    
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Invalid nonce');
    
    // Verify that verifySignature was not called
    expect(cryptoModule.verifySignature).not.toHaveBeenCalled();
  });

  it('should handle exceptions during validation', async () => {
    // Mock the validateNonce function to return valid
    vi.spyOn(nonceModule, 'validateNonce').mockReturnValue({ valid: true });
    
    // Mock the verifySignature function to throw an error
    vi.spyOn(cryptoModule, 'verifySignature').mockRejectedValue(new Error('Test error'));
    
    // Mock other necessary functions
    vi.spyOn(cryptoModule, 'padNonce').mockReturnValue(new Uint8Array(32));
    
    const result = await validateSignature({
      signature: 'base64signature',
      message: 'Hello, world!',
      publicKey: 'ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T',
      nonce: '1609459200000',
      recipient: 'api.example.com',
    });
    
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Test error');
  });
});
