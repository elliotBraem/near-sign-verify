/**
 * Auth header creation for NEAR Simple Signing
 */

import type { NearAuthData } from '../types.js';

/**
 * Create a properly formatted auth header for API authentication
 * @param authData NEAR authentication data
 * @returns Auth header string
 */
export function createAuthHeader(authData: NearAuthData): string {
  return JSON.stringify(authData);
}
