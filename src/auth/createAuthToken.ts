import type { NearAuthData } from "../types.js";

/**
 * Create properly formatted auth token for API authentication
 * @param authData NEAR authentication data
 * @returns Auth token string
 */
export function createAuthToken(authData: NearAuthData): string {
  return JSON.stringify(authData);
}
