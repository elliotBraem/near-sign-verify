import * as borsh from "borsh";
import type { NearAuthData } from "../types.js";
import { uint8ArrayToBase64 } from "../utils/encoding.js";
import {
  nearAuthDataBorshSchema,
  prepareBorshData,
} from "./authTokenSchema.js";

/**
 * Create properly formatted auth token for API authentication
 * @param authData NEAR authentication data
 * @returns Auth token string (Base64 encoded Borsh serialized data)
 */
export function createAuthToken(authData: NearAuthData): string {
  const borshData = prepareBorshData(authData);

  const serialized = borsh.serialize(nearAuthDataBorshSchema, borshData);

  return uint8ArrayToBase64(serialized);
}
