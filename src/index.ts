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

export {
  canControlStealthAddress,
  generateStealthAddress,
  checkStealthAddress,
  computeStealthPrivateKey,
  deriveStealthKeys
} from "./stealth/crypto";

export {
  generateBIP39Wallet,
  createWalletFromMnemonic,
  deriveWalletFromMnemonic,
} from "./wallet/generate";

// Backup and Recovery
export { BackupManager, BackupStorage } from "./backup";
export { SocialRecoveryManager } from "./recovery";
export { VaultSync, DeviceManager, PlatformDetector } from "./sync";
export { RecoverySimulator, getExplainer, getAllTopics, searchExplainers } from "./education";

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
