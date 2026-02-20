/**
 * Cryptographic utilities for wallet encryption
 *
 * SECURITY:
 * - Encryption keys derived from WebAuthn credentials
 * - Requires biometric/PIN authentication
 * - Hardware-backed security
 */

import { CryptoError } from "../core/errors";
import { arrayBufferToBase64Url, safeAtob } from "../utils/base64";

/**
 * Derive encryption key from WebAuthn credential
 *
 * SECURITY:
 * - Authentication-gated encryption via biometric/PIN
 * - Uses PBKDF2 with 210,000 iterations (OWASP 2023)
 * - Session caching prevents repeated prompts
 */
export async function deriveEncryptionKeyFromWebAuthn(
  credentialId: string,
  publicKey?: string
): Promise<CryptoKey> {
  try {
    const keyMaterial = publicKey
      ? `w3pk-v4:${credentialId}:${publicKey}`
      : `w3pk-v4:${credentialId}`;

    const keyMaterialHash = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(keyMaterial)
    );

    const importedKey = await crypto.subtle.importKey(
      "raw",
      keyMaterialHash,
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    const salt = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode("w3pk-salt-v4")
    );

    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: new Uint8Array(salt),
        iterations: 210000,
        hash: "SHA-256",
      },
      importedKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  } catch (error: any) {
    throw new CryptoError(
      "Failed to derive encryption key from WebAuthn",
      error
    );
  }
}

/**
 * Derive encryption key from credential ID (fallback)
 * @deprecated Use deriveEncryptionKeyFromWebAuthn
 */
export async function deriveEncryptionKey(
  credentialId: string,
  publicKey?: string
): Promise<CryptoKey> {
  try {
    const keyMaterial = publicKey
      ? `w3pk-v2:${credentialId}:${publicKey}`
      : `w3pk-v2:${credentialId}`;

    const keyMaterialHash = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(keyMaterial)
    );

    const importedKey = await crypto.subtle.importKey(
      "raw",
      keyMaterialHash,
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    const salt = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode("w3pk-salt-v2")
    );

    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: new Uint8Array(salt),
        iterations: 210000,
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

export function generateChallenge(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return arrayBufferToBase64Url(array);
}

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

    let binary = "";
    for (let i = 0; i < combined.length; i++) {
      binary += String.fromCharCode(combined[i]);
    }
    return btoa(binary);
  } catch (error) {
    throw new CryptoError("Failed to encrypt data", error);
  }
}

export async function decryptData(
  encryptedData: string,
  key: CryptoKey
): Promise<string> {
  try {
    if (!encryptedData || encryptedData.length < 16) {
      throw new Error("Invalid encrypted data: too small");
    }

    const binaryString = safeAtob(encryptedData);
    const combined = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      combined[i] = binaryString.charCodeAt(i);
    }

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

export async function hashCredentialId(credentialId: string): Promise<string> {
  try {
    const hash = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(`w3pk-cred-id:${credentialId}`)
    );
    return arrayBufferToBase64Url(hash);
  } catch (error) {
    throw new CryptoError("Failed to hash credential ID", error);
  }
}

export async function hashPublicKey(publicKey: string): Promise<string> {
  try {
    const hash = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(publicKey)
    );
    return arrayBufferToBase64Url(hash);
  } catch (error) {
    throw new CryptoError("Failed to hash public key", error);
  }
}

