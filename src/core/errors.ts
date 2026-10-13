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

/**
 * The passkey authenticated, but this device has no credential metadata.
 * The app should start a sync or restore flow.
 */
export class SyncRequiredError extends Web3PasskeyError {
  constructor(public credentialId: string) {
    super(
      "Passkey authenticated but this device has no data for it. Sync this device or restore from a backup.",
      "SYNC_REQUIRED"
    );
    this.name = "SyncRequiredError";
  }
}

/**
 * The credential metadata is on this device, but the wallet record is gone.
 * The app should offer a restore from backup.
 */
export class WalletMissingError extends Web3PasskeyError {
  constructor(
    public credentialId: string,
    public ethereumAddress: string
  ) {
    super(
      "Passkey authenticated but no wallet was found on this device. Restore it from a backup.",
      "WALLET_MISSING"
    );
    this.name = "WalletMissingError";
  }
}
