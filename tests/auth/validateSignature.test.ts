import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { validateSignature } from '../../src/auth/validateSignature.js';
import * as cryptoModule from '../../src/crypto/crypto.js';
import * as nonceModule from '../../src/utils/nonce.js';
import type { NearAuthData } from '../../src/types.js';

vi.mock('../../src/crypto/crypto.js');
vi.mock('../../src/utils/nonce.js');

describe('validateSignature', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('should validate a valid signature', async () => {
    vi.spyOn(nonceModule, 'validateNonce').mockReturnValue({ valid: true });
    
    vi.spyOn(cryptoModule, 'verifySignature').mockResolvedValue(true);
    
    vi.spyOn(cryptoModule, 'padNonce').mockReturnValue(new Uint8Array(32));
    
    const authData: NearAuthData = {
      account_id: 'test.near',
      public_key: 'ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T',
      signature: 'base64signature',
      message: 'Hello, world!',
      nonce: '1609459200000',
      recipient: 'recipient.near',
    };
    
    const result = await validateSignature(authData);
    
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
    
    expect(nonceModule.validateNonce).toHaveBeenCalledWith('1609459200000');
    expect(cryptoModule.padNonce).toHaveBeenCalledWith('1609459200000');
    expect(cryptoModule.verifySignature).toHaveBeenCalled();
  });

  it('should reject an invalid signature', async () => {
    vi.spyOn(nonceModule, 'validateNonce').mockReturnValue({ valid: true });
    
    vi.spyOn(cryptoModule, 'verifySignature').mockResolvedValue(false);
    
    vi.spyOn(cryptoModule, 'padNonce').mockReturnValue(new Uint8Array(32));
    
    const authData: NearAuthData = {
      account_id: 'test.near',
      public_key: 'ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T',
      signature: 'invalidsignature',
      message: 'Hello, world!',
      nonce: '1609459200000',
      recipient: 'recipient.near',
    };
    
    const result = await validateSignature(authData);
    
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Invalid signature');
  });

  it('should reject if nonce validation fails', async () => {
    vi.spyOn(nonceModule, 'validateNonce').mockReturnValue({
      valid: false,
      error: 'Invalid nonce',
    });
    
    const authData: NearAuthData = {
      account_id: 'test.near',
      public_key: 'ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T',
      signature: 'base64signature',
      message: 'Hello, world!',
      nonce: 'invalid-nonce',
      recipient: 'recipient.near',
    };
    
    const result = await validateSignature(authData);
    
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Invalid nonce');
    
    expect(cryptoModule.verifySignature).not.toHaveBeenCalled();
  });

  it('should handle exceptions during validation', async () => {
    vi.spyOn(nonceModule, 'validateNonce').mockReturnValue({ valid: true });
    
    vi.spyOn(cryptoModule, 'verifySignature').mockRejectedValue(new Error('Test error'));
    
    vi.spyOn(cryptoModule, 'padNonce').mockReturnValue(new Uint8Array(32));
    
    const authData: NearAuthData = {
      account_id: 'test.near',
      public_key: 'ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T',
      signature: 'base64signature',
      message: 'Hello, world!',
      nonce: '1609459200000',
      recipient: 'recipient.near',
    };
    
    const result = await validateSignature(authData);
    
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Test error');
  });
});
