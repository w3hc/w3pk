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
  | "NO_CREDENTIAL"
  | "CREDENTIAL_MISMATCH"
  | "PUBLIC_KEY_MISMATCH";

const SYNC_BOOTSTRAP_MESSAGES: Record<SyncBootstrapReason, string> = {
  NO_CREDENTIAL:
    "This backup doesn't name its passkey, so it can't set up this device. Create a new password backup on a device where you're logged in.",
  CREDENTIAL_MISMATCH:
    "This backup belongs to a different passkey than the one selected.",
  PUBLIC_KEY_MISMATCH:
    "The passkey's signature doesn't match the public key in this backup. The backup may have been tampered with.",
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

/**
 * The backup holds another wallet than the one this passkey opens on this
 * device. Restoring it replaces that wallet, so the app must confirm it
 * with the user and pass `allowAddressChange: true`.
 */
export class AddressChangeError extends Web3PasskeyError {
  constructor(
    public currentAddress: string,
    public newAddress: string
  ) {
    super(
      `This backup holds wallet ${newAddress}, not ${currentAddress}. Restoring it replaces the wallet on this device.`,
      "ADDRESS_CHANGE_NOT_ALLOWED"
    );
    this.name = "AddressChangeError";
  }
}

/**
 * The backup uses the removed `passkey` or `hybrid` method, whose key came
 * from public data rather than from the passkey. It can't be restored.
 */
export class RemovedBackupMethodError extends Web3PasskeyError {
  constructor(public method: string) {
    super(
      `This ${method} backup is no longer supported: its key came from the passkey's public data, not from the passkey. Create a new password or PRF backup on a device where you're logged in.`,
      "BACKUP_METHOD_REMOVED"
    );
    this.name = "RemovedBackupMethodError";
  }
}

const V2_TOOL_URL = "https://github.com/w3hc/w3pk/blob/v0.10.6/standalone/extract-mnemonic.html";
const V3_TOOL_URL =
  "https://github.com/w3hc/w3pk/blob/b14c32c658cc740aff78a1bbdb1cdb75c3b15a87/standalone/extract-mnemonic.html";

/**
 * The backup file isn't BackupFile v4. w3pk restores v4 files only: decrypt
 * an older password backup offline with the extract-mnemonic tool that
 * reads its format, then create a new backup.
 */
export class UnsupportedBackupVersionError extends Web3PasskeyError {
  /** The rebuilt file, when it came from guardian shares, for the offline tool */
  public backupFileJson?: string;

  constructor(public version: unknown, method?: string) {
    const format = version === undefined ? "v2 or earlier" : `version ${String(version)}`;
    const next =
      method === "prf"
        ? "Export a new backup with exportForSync() on a device where the wallet is."
        : version === 3
          ? `Decrypt a v3 password backup with the offline tool that reads v3 (${V3_TOOL_URL}), then create a new backup.`
          : `Decrypt a v2 password backup with the v0.10.6 offline tool (${V2_TOOL_URL}), then create a new backup.`;
    super(
      `This backup file uses an unsupported format (${format}). w3pk restores BackupFile v4 only. ${next}`,
      "BACKUP_VERSION_UNSUPPORTED"
    );
    this.name = "UnsupportedBackupVersionError";
  }
}

/**
 * The password for a password backup is too weak to resist an offline
 * guess: `feedback` lists what it's missing
 */
export class WeakPasswordError extends Web3PasskeyError {
  constructor(public feedback: string[]) {
    super(`Password is too weak: ${feedback.join("; ")}`, "WEAK_PASSWORD");
    this.name = "WeakPasswordError";
  }
}

export type ZkArtifactName = "wasm" | "zkey";

/**
 * A circuit artifact's IPFS CID doesn't match the CID pinned onchain,
 * so it isn't the circuit the app chose.
 */
export class ZkArtifactMismatchError extends Web3PasskeyError {
  constructor(
    public artifact: ZkArtifactName,
    public expectedCid: string,
    public actualCid: string
  ) {
    super(
      `The ${artifact} artifact's CID ${actualCid} doesn't match the pinned CID ${expectedCid}.`,
      "ZK_ARTIFACT_MISMATCH"
    );
    this.name = "ZkArtifactMismatchError";
  }
}
