/**
 * Input validation utilities
 */

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
 * Validates password strength based on security best practices
 * @param password - The password to validate
 * @returns true if password meets strength requirements, false otherwise
 *
 * Requirements:
 * - At least 12 characters long
 * - Contains at least one uppercase letter
 * - Contains at least one lowercase letter
 * - Contains at least one number
 * - Contains at least one special character
 * - Not a common password
 */
export function isStrongPassword(password: string): boolean {
  // Length check
  if (password.length < 12) {
    return false;
  }

  // Character requirements
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecialChar = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);

  if (!hasUppercase || !hasLowercase || !hasNumber || !hasSpecialChar) {
    return false;
  }

  // Common password check
  const commonPasswords = [
    'password',
    '12345678',
    'qwerty',
    'abc123',
    'password123',
    'admin',
    'letmein',
  ];

  if (commonPasswords.some((common) => password.toLowerCase().includes(common))) {
    return false;
  }

  return true;
}
