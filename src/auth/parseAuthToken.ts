import * as borsh from "borsh";
// import { z } from "zod"; // Zod validation removed for now, can be re-added for NearAuthTokenPayload
import type { NearAuthTokenPayload } from "../types.js";
import { base64ToUint8Array } from "../utils/encoding.js";
// import { createValidationErrorMessage } from "../utils/validation.js"; // If Zod is re-added
import { nearAuthTokenPayloadBorshSchema } from "./authTokenSchema.js";

/**
 * Parse a NEAR auth token into NearAuthTokenPayload.
 * @param authToken The authorization token string (Base64 encoded Borsh serialized NearAuthTokenPayload).
 * @returns NearAuthTokenPayload.
 * @throws Error if the token is invalid or deserialization fails.
 */
export function parseAuthToken(authToken: string): NearAuthTokenPayload {
  try {
    // Convert from Base64 and deserialize using Borsh
    const serialized = base64ToUint8Array(authToken);
    const deserialized = borsh.deserialize(
      nearAuthTokenPayloadBorshSchema,
      serialized,
    ) as NearAuthTokenPayload; // Assuming direct deserialization to the target type

    if (!deserialized) {
      throw new Error("Deserialization failed: result is null or undefined.");
    }

    // Ensure signed_nonce is a Uint8Array, as Borsh might return a plain array of numbers
    // depending on the exact 'borsh' library version and schema definition.
    // The schema { array: { type: "u8", len: 32 } } should handle this, but a check can be good.
    if (
      !(deserialized.signed_nonce instanceof Uint8Array) &&
      Array.isArray(deserialized.signed_nonce)
    ) {
      deserialized.signed_nonce = new Uint8Array(deserialized.signed_nonce);
    } else if (!(deserialized.signed_nonce instanceof Uint8Array)) {
      // This case should ideally not happen if deserialization is correct
      // and schema enforces Uint8Array or a structure convertible to it.
      throw new Error(
        "Deserialized signed_nonce is not a Uint8Array or an array of numbers.",
      );
    }


    // TODO: Consider re-adding Zod validation for NearAuthTokenPayload if complex validation rules are needed.
    // For now, we rely on Borsh deserialization and type casting.
    return deserialized;
  } catch (error) {
    // if (error instanceof z.ZodError) { // If Zod is re-added
    //   throw new Error(
    //     `Invalid auth data: ${createValidationErrorMessage(error)}`,
    //   );
    // }
    if (error instanceof Error) {
      throw new Error(
        `Invalid auth token: ${error.message.replace(/^Error: /, "")}`,
      );
    }
    throw new Error(`Invalid auth token: ${String(error)}`);
  }
}
