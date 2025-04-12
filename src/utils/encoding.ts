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

/**
 * Convert base64 string to Uint8Array
 * @param base64 Base64 string
 * @returns Uint8Array
 */
export function base64ToUint8Array(base64: string): Uint8Array {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

/**
 * Convert Uint8Array to base64 string
 * @param arr Uint8Array to convert
 * @returns Base64 string
 */
export function uint8ArrayToBase64(arr: Uint8Array): string {
  return btoa(String.fromCharCode.apply(null, Array.from(arr)));
}
