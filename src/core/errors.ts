/**
 * Custom error classes for better error handling
 */

export class Web3PasskeyError extends Error {
  constructor(
    message: string,
    public code: string,
    public originalError?: unknown
  ) {
    super(message);
    this.name = "Web3PasskeyError";
  }
}

export class AuthenticationError extends Web3PasskeyError {
  constructor(message: string, originalError?: unknown) {
    super(message, "AUTHENTICATION_ERROR", originalError);
    this.name = "AuthenticationError";
  }
}

export class RegistrationError extends Web3PasskeyError {
  constructor(message: string, originalError?: unknown) {
    super(message, "REGISTRATION_ERROR", originalError);
    this.name = "RegistrationError";
  }
}

export class WalletError extends Web3PasskeyError {
  constructor(message: string, originalError?: unknown) {
    super(message, "WALLET_ERROR", originalError);
    this.name = "WalletError";
  }
}

export class CryptoError extends Web3PasskeyError {
  constructor(message: string, originalError?: unknown) {
    super(message, "CRYPTO_ERROR", originalError);
    this.name = "CryptoError";
  }
}

export class StorageError extends Web3PasskeyError {
  constructor(message: string, originalError?: unknown) {
    super(message, "STORAGE_ERROR", originalError);
    this.name = "StorageError";
  }
}

export class ApiError extends Web3PasskeyError {
  constructor(
    message: string,
    public statusCode?: number,
    originalError?: unknown
  ) {
    super(message, "API_ERROR", originalError);
    this.name = "ApiError";
  }
}
