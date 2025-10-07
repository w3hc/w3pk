/**
 * Cryptographic utilities for wallet encryption
 */

import { CryptoError } from "../core/errors";

/**
 * Derives an encryption key from WebAuthn credential data
 */
export async function deriveEncryptionKey(
  credentialId: string,
  challenge: string
): Promise<CryptoKey> {
  try {
    const keyMaterial = new TextEncoder().encode(credentialId + challenge);

    const importedKey = await crypto.subtle.importKey(
      "raw",
      keyMaterial,
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: new TextEncoder().encode("webauthn-wallet-salt-w3pk"),
        iterations: 100000,
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
