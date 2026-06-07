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
 * Derive encryption key from WebAuthn PRF extension
 *
 * SECURITY:
 * - Uses WebAuthn PRF (prf/hmac-secret) extension to obtain authenticator secret
 * - Random unique salt stored with ciphertext (no precomputation attacks)
 * - Uses PBKDF2 with 210,000 iterations (OWASP 2023)
 * - Key material depends on authenticator-held secret, not public credential ID
 *
 * Fixes OPUS audit findings #1 and #3:
 * - #1 (Critical): Now uses PRF output (secret) instead of credentialId/publicKey (public)
 * - #3 (High): Now uses random salts instead of hardcoded "w3pk-salt-v4"
 *
 * TODO: Full SDK integration requires updating:
 * - src/core/sdk.ts (7 call sites)
 * - src/core/persistent-session.ts
 * - src/backup/backup-file.ts
 * - src/sync/vault.ts
 * - src/auth/authenticate.ts (to enable PRF and capture output)
 *
 * @param prfOutput - The PRF output from WebAuthn assertion (32-byte secret from authenticator)
 * @param salt - Random salt (generate with generateSalt(), store with ciphertext)
 * @returns Encryption key derived from authenticator secret
 */
export async function deriveEncryptionKeyFromWebAuthn(
  prfOutput: ArrayBuffer,
  salt: Uint8Array
): Promise<CryptoKey> {
  try {
    // Validate inputs
    if (prfOutput.byteLength !== 32) {
      throw new Error("PRF output must be 32 bytes");
    }
    if (salt.byteLength !== 32) {
      throw new Error("Salt must be 32 bytes");
    }

    // Import the PRF output as key material
    const importedKey = await crypto.subtle.importKey(
      "raw",
      prfOutput,
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    // Derive AES-GCM key using PBKDF2
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
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
      "Failed to derive encryption key from WebAuthn PRF",
      error
    );
  }
}

/**
 * Generate a random salt for encryption
 * Store this with the ciphertext for decryption
 */
export function generateSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Helper to derive encryption key with automatic fallback
 * Uses PRF if available, falls back to legacy method
 *
 * @param prfOutput - PRF output from WebAuthn (if available)
 * @param salt - Random salt (if using PRF)
 * @param credentialId - Credential ID (fallback for legacy)
 * @param publicKey - Public key (fallback for legacy)
 * @returns Encryption key
 */
export async function deriveEncryptionKeyAuto(
  prfOutput: ArrayBuffer | undefined,
  salt: Uint8Array | undefined,
  credentialId: string,
  publicKey?: string
): Promise<CryptoKey> {
  // Use PRF-based derivation if available
  if (prfOutput && salt) {
    return deriveEncryptionKeyFromWebAuthn(prfOutput, salt);
  }

  // Fall back to legacy (insecure)
  console.warn(
    "⚠️ SECURITY WARNING: Using insecure legacy encryption. " +
    "Wallet is vulnerable to offline decryption attacks. " +
    "Migrate to PRF-based encryption immediately."
  );

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
 * Derive encryption key from credential ID (v2 fallback)
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

