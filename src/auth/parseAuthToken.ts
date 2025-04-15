import * as borsh from "borsh";
import { z } from "zod";
import {
  NearAuthDataSchema,
  type NearAuthData,
  type BorshNearAuthData,
} from "../types.js";
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
    // Convert from Base64 and deserialize using Borsh
    const serialized = base64ToUint8Array(authToken);
    const deserialized = borsh.deserialize(
      nearAuthDataBorshSchema,
      serialized,
    ) as BorshNearAuthData;

    if (!deserialized) {
      throw new Error("Deserialization failed: null result");
    }

    // Validate and transform with Zod schema (handles nonce conversion)
    return NearAuthDataSchema.parse(deserialized);
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new Error(
        `Invalid auth data: ${createValidationErrorMessage(error)}`,
      );
    }
    if (error instanceof Error) {
      throw new Error(
        `Invalid auth token: ${error.message.replace(/^Error: /, "")}`,
      );
    }
    throw new Error(`Invalid auth token: ${String(error)}`);
  }
}
