/**
 * Encryption utilities for backup system
 * BackupFile v3 password mode: Argon2id + AES-256-GCM
 */

import { argon2idAsync } from "@noble/hashes/argon2.js";
import { WeakPasswordError } from "../core/errors";

export interface Argon2idParams {
  /** Memory cost in KiB */
  memoryKiB: number;
  /** Number of passes over memory */
  passes: number;
  parallelism: number;
}

/**
 * Argon2id parameters for new password backups: RFC 9106's second
 * recommendation (64 MiB, 3 passes, 4 lanes), about 1-2 s in pure JS.
 * Each file records its parameters, so older backups made with OWASP's
 * minimum (19 MiB, 2 passes, 1 lane) still restore.
 */
export const ARGON2ID_PARAMS: Readonly<Argon2idParams> = Object.freeze({
  memoryKiB: 65536,
  passes: 3,
  parallelism: 4,
});

/**
 * Upper bounds accepted from a backup file, so a file can't stall the page:
 * RFC 9106's second recommendation, the parameters of new backups
 */
export const ARGON2ID_MAX_PARAMS: Readonly<Argon2idParams> = Object.freeze({
  memoryKiB: 65536,
  passes: 3,
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
 * @throws WeakPasswordError when validatePasswordStrength() refuses the password
 */
export function assertStrongPassword(password: string): void {
  const { valid, feedback } = validatePasswordStrength(typeof password === "string" ? password : "");
  if (!valid) throw new WeakPasswordError(feedback);
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
