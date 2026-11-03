/**
 * Cryptographic utilities for wallet encryption
 *
 * SECURITY:
 * - Encryption keys derived from the passkey's WebAuthn PRF output
 * - Released only on a user-verified assertion
 */

import { CryptoError } from "../core/errors";
import {
  arrayBufferToBase64Url,
  base64UrlToArrayBuffer,
  safeAtob,
} from "../utils/base64";

/**
 * Fixed input for the WebAuthn PRF extension.
 *
 * The PRF output is HMAC(credential-scoped authenticator secret, input), so a
 * fixed input yields a per-credential secret that is DETERMINISTIC across
 * assertions (required: the key derived at one login must decrypt what a
 * previous login encrypted) yet never exists outside the authenticator.
 * Randomizing this input is what made the pre-#126 PRF integration
 * unfinishable — outputs could never be reproduced at the next login.
 */
export const PRF_INPUT = new TextEncoder().encode("w3pk-prf-input-v1");

const PRF_HKDF_INFO = new TextEncoder().encode("w3pk-prf-session-key-v1");

const PRF_WALLET_HKDF_INFO = new TextEncoder().encode("w3pk-prf-wallet-key-v1");

async function derivePrfAesKey(
  prfOutput: BufferSource,
  info: Uint8Array<ArrayBuffer>,
  extractable: boolean
): Promise<CryptoKey> {
  const byteLength = prfOutput.byteLength;
  if (byteLength !== 32) {
    throw new Error(`PRF output must be 32 bytes, got ${byteLength}`);
  }

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    prfOutput,
    "HKDF",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    extractable,
    ["encrypt", "decrypt"]
  );
}

/**
 * Derive the persistent-session encryption key from a WebAuthn PRF output.
 *
 * SECURITY:
 * - The PRF output is a 32-byte secret released by the authenticator only
 *   during a user-verified assertion — unlike credentialId/publicKey, it is
 *   not derivable from anything stored on disk.
 * - HKDF-SHA256 (PRF output is full-entropy key material; no stretching
 *   needed) into an AES-GCM key, non-extractable unless `extractable` is set
 *   so that silent restore (requireReauth: false) can store it.
 */
export async function derivePrfSessionKey(
  prfOutput: BufferSource,
  extractable = false
): Promise<CryptoKey> {
  try {
    return await derivePrfAesKey(prfOutput, PRF_HKDF_INFO, extractable);
  } catch (error: any) {
    throw new CryptoError("Failed to derive session key from PRF output", error);
  }
}

/**
 * Derive the key that encrypts the wallet stored on the device from the PRF
 * output at `PRF_INPUT`. Same PRF output as the session key, separate HKDF
 * info, so neither key reveals the other. Never extractable.
 */
export async function deriveWalletKey(prfOutput: BufferSource): Promise<CryptoKey> {
  try {
    return await derivePrfAesKey(prfOutput, PRF_WALLET_HKDF_INFO, false);
  } catch (error: any) {
    throw new CryptoError("Failed to derive wallet key from PRF output", error);
  }
}

/**
 * Export an extractable PRF session key as base64url, for silent restore
 */
export async function exportSessionKey(key: CryptoKey): Promise<string> {
  try {
    return arrayBufferToBase64Url(await crypto.subtle.exportKey("raw", key));
  } catch (error: any) {
    throw new CryptoError("Failed to export session key", error);
  }
}

/**
 * Import a stored PRF session key as a non-extractable AES-GCM key
 */
export async function importSessionKey(rawKey: string): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey(
      "raw",
      base64UrlToArrayBuffer(rawKey),
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  } catch (error: any) {
    throw new CryptoError("Failed to import session key", error);
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
