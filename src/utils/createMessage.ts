import { generateNonce } from "./nonce.js";
import { uint8ArrayToBase64 } from "./encoding.js";
import type { MessageData } from "../types.js";

export function createMessage(options: {
  recipient: string;
  nonce?: Uint8Array;
  data?: string | Record<string, any>;
}): { message: string; nonce: Uint8Array } {
  const currentNonce = options.nonce || generateNonce();

  if (options.data && JSON.stringify(options.data).length > 10000) {
    throw new Error("Data payload too large (max 10KB)");
  }

  const messageData: MessageData = {
    nonce: uint8ArrayToBase64(currentNonce),
    timestamp: Date.now(),
    recipient: options.recipient,
  };

  if (options.data !== undefined) {
    messageData.data = options.data;
  }

  return {
    message: JSON.stringify(messageData),
    nonce: currentNonce,
  };
}
