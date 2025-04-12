import { describe, it, expect } from 'vitest';
import { createAuthToken } from '../../src/auth/createAuthToken.js';
import type { NearAuthData } from '../../src/types.js';

describe('createAuthToken', () => {
  it('should create a properly formatted auth header', () => {
    const authData: NearAuthData = {
      account_id: 'test.near',
      public_key: 'ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T',
      signature: 'base64signature',
      message: 'Hello, world!',
      nonce: '1609459200000',
      recipient: 'recipient.near',
    };

    const header = createAuthToken(authData);
    
    // Header should be a JSON string
    expect(typeof header).toBe('string');
    
    // Should be valid JSON
    const parsed = JSON.parse(header);
    
    // Should contain all the original data
    expect(parsed).toEqual(authData);
  });


  it('should include callback_url when provided', () => {
    const authData: NearAuthData = {
      account_id: 'test.near',
      public_key: 'ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T',
      signature: 'base64signature',
      message: 'Hello, world!',
      nonce: '1609459200000',
      recipient: 'recipient.near',
      callback_url: 'https://example.com/callback',
    };

    const header = createAuthToken(authData);
    const parsed = JSON.parse(header);
    
    expect(parsed.callback_url).toBe('https://example.com/callback');
  });
});
