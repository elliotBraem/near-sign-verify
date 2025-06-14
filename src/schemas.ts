import { b } from "@zorsh/zorsh";

/**
 * Zorsh schema for NearAuthPayload (what gets hashed and signed)
 */
export const NearAuthPayloadSchema = b.struct({
  tag: b.u32(),
  message: b.string(),
  nonce: b.array(b.u8(), 32),
  receiver: b.string(),
  callback_url: b.option(b.string()),
});

/**
 * Zorsh schema for NearAuthData (the full auth token data)
 * Note: zorsh uses number[] for arrays, but our API uses Uint8Array
 */
export const NearAuthDataSchema = b.struct({
  account_id: b.string(),
  public_key: b.string(),
  signature: b.string(),
  message: b.string(),
  nonce: b.array(b.u8(), 32),
  recipient: b.string(),
  callback_url: b.option(b.string()),
});

/**
 * TypeScript types inferred from zorsh schemas
 */
export type NearAuthPayload = b.infer<typeof NearAuthPayloadSchema>;
export type NearAuthData = b.infer<typeof NearAuthDataSchema>;
