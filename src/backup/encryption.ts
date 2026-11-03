/**
 * Encryption utilities for backup system
 * BackupFile v3 password mode: Argon2id + AES-256-GCM
 */

import { argon2idAsync } from "@noble/hashes/argon2.js";
import { WeakPasswordError } from "../core/errors";
import { COMMON_PASSWORDS } from "./common-passwords";

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

export const PASSWORD_MIN_LENGTH = 15;
export const PASSWORD_MAX_LENGTH = 256;

/**
 * Password rules for backups, after NIST SP 800-63B-4 §3.1.1.2 and the OWASP
 * Authentication Cheat Sheet: the NFC-normalized password must have 15 to 256
 * Unicode code points, not be a common password (whole match, any case,
 * ignoring spaces, dots, dashes and underscores) and not repeat a single
 * character. No composition rules; spaces and any Unicode character are accepted.
 */
export function validatePasswordStrength(password: string): {
  valid: boolean;
  feedback: string[];
} {
  const normalized = typeof password === "string" ? password.normalize("NFC") : "";
  const codePoints = [...normalized];
  const length = codePoints.length;
  const folded = normalized.toLowerCase();
  const feedback: string[] = [];

  if (length < PASSWORD_MIN_LENGTH) {
    feedback.push(`Password must be at least ${PASSWORD_MIN_LENGTH} characters`);
  }
  if (length > PASSWORD_MAX_LENGTH) {
    feedback.push(`Password must be at most ${PASSWORD_MAX_LENGTH} characters`);
  }
  if (COMMON_PASSWORDS.has(folded) || COMMON_PASSWORDS.has(folded.replace(/[\s._-]+/gu, ""))) {
    feedback.push("Password is too common");
  }
  if (length > 1 && new Set(codePoints).size === 1) {
    feedback.push("Password must not repeat a single character");
  }

  return { valid: feedback.length === 0, feedback };
}

/**
 * @throws WeakPasswordError when validatePasswordStrength() refuses the password
 */
export function assertStrongPassword(password: string): void {
  const { valid, feedback } = validatePasswordStrength(password);
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
