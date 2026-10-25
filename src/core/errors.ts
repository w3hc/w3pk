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

export type SyncBootstrapReason =
  | "PASSKEY_BACKUP"
  | "NO_CREDENTIAL"
  | "CREDENTIAL_MISMATCH";

const SYNC_BOOTSTRAP_MESSAGES: Record<SyncBootstrapReason, string> = {
  PASSKEY_BACKUP:
    "This device has no data for the passkey, and a passkey-encrypted backup can't set it up. Sync with a password backup instead.",
  NO_CREDENTIAL:
    "This backup doesn't name its passkey, so it can't set up this device. Create a new password backup on a device where you're logged in.",
  CREDENTIAL_MISMATCH:
    "This backup belongs to a different passkey than the one selected.",
};

/**
 * A sync can't set up this device's passkey metadata from the backup.
 */
export class SyncBootstrapError extends Web3PasskeyError {
  constructor(
    public reason: SyncBootstrapReason,
    public credentialId: string
  ) {
    super(SYNC_BOOTSTRAP_MESSAGES[reason], "SYNC_BOOTSTRAP_FAILED");
    this.name = "SyncBootstrapError";
  }
}

/**
 * The authenticator returned no WebAuthn PRF output, so no
 * passkey-bound secret can be derived. There is no fallback.
 */
export class PrfUnsupportedError extends Web3PasskeyError {
  constructor(public credentialId: string) {
    super(
      "This passkey's authenticator doesn't support the WebAuthn PRF extension.",
      "PRF_UNSUPPORTED"
    );
    this.name = "PrfUnsupportedError";
  }
}
