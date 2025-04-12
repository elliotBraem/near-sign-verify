import * as borsh from "borsh";
import { z } from "zod";
import { NearAuthDataSchema, type NearAuthData } from "../types.js";
import { base64ToUint8Array } from "../utils/encoding.js";
import { createValidationErrorMessage } from "../utils/validation.js";
import { nearAuthDataBorshSchema } from "./authTokenSchema.js";

/**
 * Parse a NEAR auth token into NearAuthData
 * @param authToken The authorization token string (Base64 encoded Borsh serialized data)
 * @returns NearAuthData
 * @throws Error if the token is invalid or missing required fields
 */
export function parseAuthToken(authToken: string): NearAuthData {
  try {
    // Convert from Base64 to Uint8Array
    const serialized = base64ToUint8Array(authToken);

    try {
      // Deserialize using Borsh
      const deserialized = borsh.deserialize(
        nearAuthDataBorshSchema,
        serialized,
      );

      try {
        // Validate with Zod schema
        return NearAuthDataSchema.parse(deserialized);
      } catch (validationError) {
        if (validationError instanceof z.ZodError) {
          throw new Error(
            `Invalid auth data: ${createValidationErrorMessage(validationError)}`,
          );
        }
        throw validationError;
      }
    } catch (borshError) {
      const errorMessage =
        borshError instanceof Error ? borshError.message : String(borshError);
      throw new Error(
        `Invalid auth token format: Borsh deserialization failed - ${errorMessage}`,
      );
    }
  } catch (error) {
    if (error instanceof Error && error.message.includes("Invalid character")) {
      throw new Error(`Invalid auth token: ${error.message}`);
    }
    if (error instanceof Error) {
      throw error; // Re-throw errors we've already formatted
    }
    throw new Error(`Invalid auth token: ${String(error)}`);
  }
}
