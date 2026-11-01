/**
 * Encryption utilities for backup system
 * BackupFile v3 password mode: Argon2id + AES-256-GCM
 * QR backups: PBKDF2 + AES-256-GCM
 */

import { argon2idAsync } from "@noble/hashes/argon2.js";
import { safeAtob } from "../utils/base64";

export interface Argon2idParams {
  /** Memory cost in KiB */
  memoryKiB: number;
  /** Number of passes over memory */
  passes: number;
  parallelism: number;
}

/**
 * Argon2id parameters for new password backups: OWASP's first
 * recommendation (19 MiB, 2 passes, 1 lane), about 0.4 s in pure JS
 */
export const ARGON2ID_PARAMS: Readonly<Argon2idParams> = Object.freeze({
  memoryKiB: 19456,
  passes: 2,
  parallelism: 1,
});

/** Upper bounds accepted from a backup file, so a file can't stall the page */
export const ARGON2ID_MAX_PARAMS: Readonly<Argon2idParams> = Object.freeze({
  memoryKiB: 262144,
  passes: 10,
  parallelism: 4,
});

/**
 * Derive an AES-256-GCM key from a password with Argon2id (RFC 9106).
 * The password is NFC-normalized, then UTF-8 encoded.
 */
export async function deriveKeyFromPasswordArgon2id(
  password: string,
  salt: Uint8Array,
  params: Argon2idParams = ARGON2ID_PARAMS
): Promise<CryptoKey> {
  const keyBytes = await argon2idAsync(
    new TextEncoder().encode(password.normalize("NFC")),
    salt,
    { m: params.memoryKiB, t: params.passes, p: params.parallelism, dkLen: 32 }
  );
  try {
    return await crypto.subtle.importKey(
      "raw",
      keyBytes as BufferSource,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
  } finally {
    keyBytes.fill(0);
  }
}

/**
 * Derive encryption key from password using PBKDF2
 * @param password - User's password
 * @param salt - Crypto salt (32 bytes recommended)
 * @param iterations - PBKDF2 iterations (310,000 for OWASP 2025)
 */
export async function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array,
  iterations: number = 310000
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);

  // Import password as key material
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    passwordBuffer,
    "PBKDF2",
    false,
    ["deriveBits", "deriveKey"]
  );

  // Derive AES-256 key using PBKDF2
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as BufferSource,
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypt data with AES-256-GCM
 */
export async function encryptWithPassword(
  data: string,
  password: string,
  salt: Uint8Array
): Promise<{
  encrypted: string;
  iv: string;
  salt: string;
  iterations: number;
}> {
  const iterations = 310000;
  const key = await deriveKeyFromPassword(password, salt, iterations);

  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);

  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    key,
    dataBuffer
  );

  return {
    encrypted: bufferToBase64(encryptedBuffer),
    iv: bufferToBase64(iv),
    salt: bufferToBase64(salt),
    iterations,
  };
}

/**
 * Decrypt data with AES-256-GCM
 */
export async function decryptWithPassword(
  encryptedData: string,
  password: string,
  salt: string,
  iv: string,
  iterations: number = 310000
): Promise<string> {
  const saltBuffer = base64ToBuffer(salt);
  const key = await deriveKeyFromPassword(password, saltBuffer, iterations);

  const ivBuffer = base64ToBuffer(iv);
  const encryptedBuffer = base64ToBuffer(encryptedData);

  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: ivBuffer as BufferSource,
    },
    key,
    encryptedBuffer as BufferSource
  );

  const decoder = new TextDecoder();
  return decoder.decode(decryptedBuffer);
}

/**
 * Get device fingerprint for binding backups to specific device
 * Note: This is NOT cryptographically strong, just a convenience feature
 */
export async function getDeviceFingerprint(): Promise<string> {
  const components = [
    navigator.userAgent,
    navigator.language,
    new Date().getTimezoneOffset().toString(),
    screen.width + "x" + screen.height,
    screen.colorDepth.toString(),
  ];

  const fingerprintString = components.join("|");
  const encoder = new TextEncoder();
  const buffer = encoder.encode(fingerprintString);

  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  return bufferToBase64(hashBuffer);
}

/**
 * Derive address checksum for verification
 */
export async function deriveAddressChecksum(
  ethereumAddress: string
): Promise<string> {
  const encoder = new TextEncoder();
  const buffer = encoder.encode(ethereumAddress.toLowerCase());
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  return bufferToBase64(hashBuffer).substring(0, 16);
}

/**
 * Validate password strength
 */
export function validatePasswordStrength(password: string): {
  valid: boolean;
  score: number; // 0-100
  feedback: string[];
} {
  const feedback: string[] = [];
  let score = 0;

  // Length check
  if (password.length < 12) {
    feedback.push("Password must be at least 12 characters");
  } else {
    score += 25;
  }

  // Uppercase check
  if (!/[A-Z]/.test(password)) {
    feedback.push("Add at least one uppercase letter");
  } else {
    score += 15;
  }

  // Lowercase check
  if (!/[a-z]/.test(password)) {
    feedback.push("Add at least one lowercase letter");
  } else {
    score += 15;
  }

  // Number check
  if (!/[0-9]/.test(password)) {
    feedback.push("Add at least one number");
  } else {
    score += 15;
  }

  // Special character check
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    feedback.push("Add at least one special character");
  } else {
    score += 15;
  }

  // Length bonus
  if (password.length >= 16) {
    score += 10;
  }
  if (password.length >= 20) {
    score += 5;
  }

  // Common password check (simple version)
  const commonPasswords = [
    "password",
    "12345678",
    "qwerty",
    "abc123",
    "password123",
    "admin",
    "letmein",
  ];
  if (
    commonPasswords.some((common) => password.toLowerCase().includes(common))
  ) {
    feedback.push("Password is too common");
    score = Math.min(score, 25);
  }

  return {
    valid: score >= 50 && feedback.length === 0,
    score: Math.min(score, 100),
    feedback,
  };
}

/**
 * Helper: Convert ArrayBuffer to Base64
 */
function bufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  // Use regular btoa for binary data (not safeBtoa which is for Unicode text)
  return btoa(binary);
}

/**
 * Helper: Convert Base64 to ArrayBuffer
 */
function base64ToBuffer(base64: string): Uint8Array {
  const binary = safeAtob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
