import * as borsh from "borsh";
import type { NearAuthTokenPayload } from "../types.js";
import { uint8ArrayToBase64 } from "../utils/encoding.js";
import {
  nearAuthTokenPayloadBorshSchema,
  prepareNearAuthTokenPayloadForBorsh,
} from "./authTokenSchema.js";

/**
 * Create properly formatted auth token for API authentication
 * @param tokenPayload The payload containing all necessary data for the token.
 * @returns Auth token string (Base64 encoded Borsh serialized NearAuthTokenPayload)
 */
export function createAuthToken(tokenPayload: NearAuthTokenPayload): string {
  const borshData = prepareNearAuthTokenPayloadForBorsh(tokenPayload);

  const serialized = borsh.serialize(
    nearAuthTokenPayloadBorshSchema,
    borshData,
  );

  return uint8ArrayToBase64(serialized);
}
