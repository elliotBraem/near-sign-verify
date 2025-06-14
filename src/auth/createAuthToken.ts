import { base64 } from "@scure/base";
import type { NearAuthData } from "../schemas.js";
import { NearAuthDataSchema } from "../schemas.js";

/**
 * Create properly formatted auth token for API authentication
 * @param authData NEAR authentication data
 * @returns Auth token string (Base64 encoded Zorsh serialized data)
 */
export function createAuthToken(authData: NearAuthData): string {
  const serialized = NearAuthDataSchema.serialize(authData);
  return base64.encode(serialized);
}
