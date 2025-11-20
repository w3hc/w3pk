/**
 * Web3 Passkey SDK
 * Passwordless authentication with encrypted wallets
 */

import { Web3Passkey } from "./core/sdk";
import type { Web3PasskeyConfig } from "./core/config";

export function createWeb3Passkey(config: Web3PasskeyConfig = {}): Web3Passkey {
  return new Web3Passkey(config);
}

export type { Web3PasskeyConfig, StealthAddressConfig } from "./core/config";
export type { UserInfo, WalletInfo } from "./types";
export type { StealthKeys, StealthAddressResult } from "./stealth";
export type { EIP7702Authorization, SignAuthorizationParams } from "./wallet/types";

export {
  Web3PasskeyError,
  AuthenticationError,
  RegistrationError,
  WalletError,
  CryptoError,
  StorageError,
  ApiError,
} from "./core/errors";

export { Web3Passkey } from "./core/sdk";
export { StealthAddressModule } from "./stealth";

// SECURITY: Stealth address crypto functions are NOT exported
// Applications should use the StealthAddressModule through the SDK
// which properly manages authentication and sessions

// SECURITY: Wallet generation functions are NOT exported
// Applications should use sdk.generateWallet() and sdk.deriveWallet()
// which enforce origin-specific derivation and MAIN tag restrictions

// SECURITY: Origin derivation utilities exported for advanced use cases
// These are safe because they require the mnemonic to be passed in
// (which apps don't have access to)
export {
  normalizeOrigin,
  getCurrentOrigin,
  DEFAULT_TAG,
} from "./wallet/origin-derivation";

// SECURITY: Backup, Recovery, and Sync managers are NOT exported
// Applications should use SDK methods like:
// - sdk.createZipBackup()
// - sdk.createQRBackup()
// - sdk.setupSocialRecovery()
// - sdk.getBackupStatus()
// which properly manage authentication and mnemonic access

// Education utilities (safe to export - no key access)
export { RecoverySimulator, getExplainer, getAllTopics, searchExplainers } from "./education";

// Validation utilities
export {
  validateEthereumAddress,
  validateUsername,
  validateMnemonic,
  isStrongPassword,
  assertEthereumAddress,
  assertUsername,
  assertMnemonic,
} from "./utils/validation";

// Build verification utilities
export {
  getW3pkBuildHash,
  getCurrentBuildHash,
  verifyBuildHash,
  getPackageVersion,
} from "./utils/build-hash";

// Backup and Recovery Types
export type {
  BackupStatus,
  SecurityScore,
  ZipBackupOptions,
  QRBackupOptions,
  RecoveryScenario,
  SimulationResult,
  EncryptedBackupInfo,
} from "./backup/types";

export type {
  Guardian,
  GuardianInvite,
  SocialRecoveryConfig,
  RecoveryShare,
  RecoveryProgress,
} from "./recovery/types";

export type {
  SyncVault,
  DeviceInfo,
  SyncCapabilities,
  SyncStatus,
} from "./sync/types";

export default createWeb3Passkey;
