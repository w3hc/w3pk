/**
 * Cryptographic utilities for wallet encryption
 *
 * SECURITY: Encryption keys are derived from WebAuthn signatures,
 * which require biometric/PIN authentication. This prevents wallet
 * theft even if an attacker has file system access.
 */

import { CryptoError } from "../core/errors";

/**
 * Derives an encryption key from a WebAuthn signature
 *
 * CRITICAL SECURITY: The signature can only be obtained by authenticating
 * with biometrics/PIN. This ensures the encryption key is protected by
 * the authenticator, not just stored data.
 *
 * @param signature - WebAuthn assertion signature (requires authentication)
 * @param credentialId - Public credential identifier (for salt diversity)
 */
export async function deriveEncryptionKeyFromSignature(
  signature: ArrayBuffer,
  credentialId: string
): Promise<CryptoKey> {
  try {
    // Hash the signature to get uniform key material
    const signatureHash = await crypto.subtle.digest("SHA-256", signature);

    // Import the signature hash as key material
    const importedKey = await crypto.subtle.importKey(
      "raw",
      signatureHash,
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    // Use credentialId as additional salt for key diversity
    const salt = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode("w3pk-v1:" + credentialId)
    );

    // Derive the actual encryption key with strong parameters
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: new Uint8Array(salt),
        iterations: 210000, // OWASP 2023 recommendation
        hash: "SHA-256",
      },
      importedKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  } catch (error) {
    throw new CryptoError("Failed to derive encryption key", error);
  }
}

/**
 * Generates a cryptographic challenge for WebAuthn authentication
 */
export function generateChallenge(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/**
 * Encrypts data using AES-GCM
 */
export async function encryptData(
  data: string,
  key: CryptoKey
): Promise<string> {
  try {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encodedData = new TextEncoder().encode(data);

    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      encodedData
    );

    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);

    return btoa(String.fromCharCode(...combined));
  } catch (error) {
    throw new CryptoError("Failed to encrypt data", error);
  }
}

/**
 * Decrypts data using AES-GCM
 */
export async function decryptData(
  encryptedData: string,
  key: CryptoKey
): Promise<string> {
  try {
    if (!encryptedData || encryptedData.length < 16) {
      throw new Error("Invalid encrypted data: too small");
    }

    const combined = new Uint8Array(
      atob(encryptedData)
        .split("")
        .map((char) => char.charCodeAt(0))
    );

    if (combined.length < 12) {
      throw new Error("Invalid encrypted data: missing IV");
    }

    const iv = combined.slice(0, 12);
    const encrypted = combined.slice(12);

    if (encrypted.length === 0) {
      throw new Error("Invalid encrypted data: no content");
    }

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      encrypted
    );

    return new TextDecoder().decode(decrypted);
  } catch (error) {
    throw new CryptoError(
      `Data decryption failed: ${
        error instanceof Error ? error.message : "Unknown error"
      }`,
      error
    );
  }
}
