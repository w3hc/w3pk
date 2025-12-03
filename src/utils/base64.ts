/**
 * Robust base64url encoding/decoding utilities
 *
 * These functions handle edge cases that can cause atob/btoa to fail:
 * - Missing padding
 * - Invalid characters
 * - Unicode issues
 */

/**
 * Converts a base64url string to ArrayBuffer with proper padding handling
 * @param base64url - Base64url encoded string (URL-safe, may be unpadded)
 * @returns ArrayBuffer containing the decoded bytes
 * @throws Error if the input is invalid
 */
export function base64UrlToArrayBuffer(base64url: string): ArrayBuffer {
  try {
    // Convert base64url to base64 (replace URL-safe chars)
    let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");

    // Add padding if needed
    // Base64 strings should be a multiple of 4 characters
    const padLength = (4 - (base64.length % 4)) % 4;
    base64 += "=".repeat(padLength);

    // Decode using atob
    const binary = atob(base64);

    // Convert to Uint8Array
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }

    return bytes.buffer;
  } catch (error) {
    throw new Error(
      `Failed to decode base64url string: ${
        error instanceof Error ? error.message : "Invalid format"
      }`
    );
  }
}

/**
 * Converts ArrayBuffer to base64url string (URL-safe, unpadded)
 * @param buffer - ArrayBuffer or Uint8Array to encode
 * @returns Base64url encoded string
 */
export function arrayBufferToBase64Url(
  buffer: ArrayBuffer | Uint8Array
): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);

  // Convert bytes to binary string
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }

  // Encode to base64 and convert to base64url (remove padding, use URL-safe chars)
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

/**
 * Converts a regular base64 string to ArrayBuffer
 * @param base64 - Standard base64 encoded string
 * @returns ArrayBuffer containing the decoded bytes
 */
export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  try {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  } catch (error) {
    throw new Error(
      `Failed to decode base64 string: ${
        error instanceof Error ? error.message : "Invalid format"
      }`
    );
  }
}

/**
 * Safe atob wrapper that handles base64url and adds padding automatically
 * @param input - Base64 or base64url encoded string
 * @returns Decoded binary string
 */
export function safeAtob(input: string): string {
  try {
    // Convert base64url to base64 if needed
    let base64 = input.replace(/-/g, "+").replace(/_/g, "/");

    // Add padding if needed
    const padLength = (4 - (base64.length % 4)) % 4;
    base64 += "=".repeat(padLength);

    return atob(base64);
  } catch (error) {
    throw new Error(
      `Failed to decode base64 string: ${
        error instanceof Error ? error.message : "Invalid format"
      }`
    );
  }
}

/**
 * Safe btoa wrapper that handles Unicode strings
 * @param input - String to encode
 * @returns Base64 encoded string
 */
export function safeBtoa(input: string): string {
  try {
    // Handle Unicode by encoding to UTF-8 first
    const bytes = new TextEncoder().encode(input);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  } catch (error) {
    throw new Error(
      `Failed to encode string: ${
        error instanceof Error ? error.message : "Invalid input"
      }`
    );
  }
}

/**
 * Alias for base64UrlToArrayBuffer - decodes base64url to ArrayBuffer
 * @param base64url - Base64url encoded string
 * @returns ArrayBuffer containing the decoded bytes
 */
export function base64UrlDecode(base64url: string): ArrayBuffer {
  return base64UrlToArrayBuffer(base64url);
}
