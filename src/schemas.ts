import { b } from "@zorsh/zorsh";

/**
 * Zorsh schema for SignedPayload (what gets hashed and signed)
 */
export const SignedPayloadSchema = b.struct({
  message: b.string(),
  nonce: b.array(b.u8(), 32), // Represents [u8; 32]
  recipient: b.string(),
  callbackUrl: b.option(b.string()), // Optional field
});

/**
 * Zorsh schema for NearAuthData (the full auth token data)
 * Note: zorsh uses number[] for arrays, but our API uses Uint8Array
 */
export const NearAuthDataSchema = b.struct({
  accountId: b.string(),
  publicKey: b.string(),
  signature: b.string(),
  message: b.string(),
  nonce: b.array(b.u8(), 32),
  recipient: b.string(),
  callbackUrl: b.option(b.string()),
  state: b.option(b.string()),
});

/**
 * TypeScript types inferred from zorsh schemas
 */
export type SignedPayload = b.infer<typeof SignedPayloadSchema>;
export type NearAuthData = b.infer<typeof NearAuthDataSchema>;
