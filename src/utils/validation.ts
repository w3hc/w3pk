/**
 * Input validation utilities
 */

import { validatePasswordStrength } from "../backup/encryption";

export function validateEthereumAddress(address: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(address);
}

export function validateUsername(username: string): boolean {
  // Length check: 3-50 characters
  if (username.length < 3 || username.length > 50) {
    return false;
  }

  // Character check: alphanumeric, underscore, and hyphen
  // Must start and end with alphanumeric (not hyphen or underscore)
  // For 3+ char usernames: ^[a-zA-Z0-9] (start) + [a-zA-Z0-9_-]* (middle) + [a-zA-Z0-9]$ (end)
  // This allows patterns like: "abc", "a-b", "a_b", "user-name", etc.
  const validUsernamePattern = /^[a-zA-Z0-9]([a-zA-Z0-9_-]*[a-zA-Z0-9])?$/;

  return validUsernamePattern.test(username);
}

export function validateMnemonic(mnemonic: string): boolean {
  const words = mnemonic.trim().split(/\s+/);
  return words.length === 12 || words.length === 24;
}

export function assertEthereumAddress(address: string): void {
  if (!validateEthereumAddress(address)) {
    throw new Error("Invalid Ethereum address format");
  }
}

export function assertUsername(username: string): void {
  if (!validateUsername(username)) {
    throw new Error(
      "Username must be 3-50 characters long and contain only letters, numbers, underscores, and hyphens. Must start and end with a letter or number."
    );
  }
}

export function assertMnemonic(mnemonic: string): void {
  if (!validateMnemonic(mnemonic)) {
    throw new Error("Invalid mnemonic: must be 12 or 24 words");
  }
}

/**
 * The password rules of backups: see validatePasswordStrength()
 */
export function isStrongPassword(password: string): boolean {
  return validatePasswordStrength(password).valid;
}
