/**
 * Convert a string to Uint8Array
 * @param str String to convert
 * @returns Uint8Array
 */
export function stringToUint8Array(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Convert Uint8Array to string
 * @param arr Uint8Array to convert
 * @returns String
 */
export function uint8ArrayToString(arr: Uint8Array): string {
  return new TextDecoder().decode(arr);
}
