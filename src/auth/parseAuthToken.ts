/**
 * Auth header parsing for NEAR Simple Signing
 */

import { z } from 'zod';
import { NearAuthDataSchema, type NearAuthData } from '../types.js';
import { createValidationErrorMessage } from '../utils/validation.js';

/**
 * Parse a NEAR auth header into NearAuthData
 * @param authToken The authorization header string
 * @returns NearAuthData
 * @throws Error if the header is invalid or missing required fields
 */
export function parseAuthToken(authToken: string): NearAuthData {
  try {
    const parsedData = JSON.parse(authToken);

    try {
      return NearAuthDataSchema.parse(parsedData);
    } catch (validationError) {
      if (validationError instanceof z.ZodError) {
        throw new Error(`Invalid auth data: ${createValidationErrorMessage(validationError)}`);
      }
      throw validationError;
    }
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new Error('Invalid auth header format: not a valid JSON string');
    }
    throw error;
  }
}
