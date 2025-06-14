import { base64 } from "@scure/base";
import type { NearAuthData } from "../schemas.js";
import { NearAuthDataSchema } from "../schemas.js";

/**
 * Parse a NEAR auth token into NearAuthData
 * @param authToken The authorization token string (Base64 encoded Zorsh serialized data)
 * @returns NearAuthData
 * @throws Error if the token is invalid or missing required fields
 */
export function parseAuthToken(authToken: string): NearAuthData {
  try {
    const serialized = base64.decode(authToken);
    const deserialized = NearAuthDataSchema.deserialize(serialized);

    if (!deserialized) {
      throw new Error("Deserialization failed: null result");
    }

    return deserialized;
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(
        `Invalid auth token: ${error.message.replace(/^Error: /, "")}`,
      );
    }
    throw new Error(`Invalid auth token: ${String(error)}`);
  }
}
