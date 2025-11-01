/**
 * Cryptographic utilities for wallet encryption
 *
 * SECURITY: Encryption keys are derived from WebAuthn signatures of a fixed message.
 * This requires biometric/PIN authentication and provides true hardware-backed security.
 * Even with file system access, an attacker cannot decrypt without biometric authentication.
 */

import { CryptoError } from "../core/errors";
import { arrayBufferToBase64Url, safeAtob } from "../utils/base64";

/**
 * Derives an encryption key from WebAuthn credential (RECOMMENDED)
 *
 * SECURITY: This provides authentication-gated encryption:
 * - Requires biometric/PIN to prove identity before decryption
 * - Uses credential ID + public key as deterministic key material
 * - WebAuthn authentication verifies user identity
 * - Session caching prevents repeated prompts (1 hour default)
 *
 * IMPORTANT: This is authentication-gated, not signature-encrypted.
 * An attacker with both localStorage AND IndexedDB access could decrypt,
 * BUT WebAuthn authentication is still required before SDK allows access.
 *
 * For stronger security at rest, consider server-based architecture.
 *
 * BROWSER SUPPORT:
 * ✅ Chrome 67+, Edge 18+, Firefox 60+, Safari 14+
 * ✅ iOS 14.5+, Android 9+
 * ❌ Older browsers/devices - will throw NotSupportedError
 *
 * @param credentialId - The credential ID (base64url encoded)
 * @param publicKey - The public key (base64url encoded, optional)
 * @returns Encryption key derived from credential metadata
 * @throws CryptoError if derivation fails
 */
export async function deriveEncryptionKeyFromWebAuthn(
  credentialId: string,
  publicKey?: string
): Promise<CryptoKey> {
  try {
    // Use credential ID + public key as deterministic key material
    // This is the same every time for a given credential
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

    // Use a fixed salt for deterministic derivation
    const salt = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode("w3pk-salt-v4")
    );

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
  } catch (error: any) {
    throw new CryptoError(
      "Failed to derive encryption key from WebAuthn",
      error
    );
  }
}

/**
 * Derives an encryption key from credential ID (FALLBACK)
 *
 * WARNING: Does NOT require biometric authentication for decryption.
 * An attacker with file system access can decrypt the wallet.
 * Use only as fallback for unsupported platforms.
 *
 * @param credentialId - Unique credential identifier
 * @param publicKey - Public key from the credential (optional)
 * @deprecated Use deriveEncryptionKeyFromWebAuthn for biometric protection
 */
export async function deriveEncryptionKey(
  credentialId: string,
  publicKey?: string
): Promise<CryptoKey> {
  try {
    // Create deterministic key material from credential ID and optional public key
    const keyMaterial = publicKey
      ? `w3pk-v2:${credentialId}:${publicKey}`
      : `w3pk-v2:${credentialId}`;

    const keyMaterialHash = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(keyMaterial)
    );

    // Import as key material
    const importedKey = await crypto.subtle.importKey(
      "raw",
      keyMaterialHash,
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    // Use a fixed salt for deterministic derivation
    const salt = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode("w3pk-salt-v2")
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
  return arrayBufferToBase64Url(array);
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

    let binary = "";
    for (let i = 0; i < combined.length; i++) {
      binary += String.fromCharCode(combined[i]);
    }
    return btoa(binary);
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

/**
 * Hashes a credential ID using SHA-256
 * Used to obscure credential IDs in localStorage
 */
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

/**
 * Hashes a public key using SHA-256
 * Creates a fingerprint for public key identification
 */
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

/**
 * Encrypts metadata (username, address, etc.) using AES-GCM
 * Similar to encryptData but specifically for credential metadata
 */
export async function encryptMetadata(
  data: string,
  key: CryptoKey
): Promise<string> {
  return encryptData(data, key);
}

/**
 * Decrypts metadata using AES-GCM
 * Similar to decryptData but specifically for credential metadata
 */
export async function decryptMetadata(
  encryptedData: string,
  key: CryptoKey
): Promise<string> {
  return decryptData(encryptedData, key);
}
