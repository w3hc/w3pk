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

export {
  normalizeOrigin,
  getCurrentOrigin,
  DEFAULT_TAG,
} from "./wallet/origin-derivation";

export { RecoverySimulator, getExplainer, getAllTopics, searchExplainers } from "./education";

export {
  validateEthereumAddress,
  validateUsername,
  validateMnemonic,
  isStrongPassword,
  assertEthereumAddress,
  assertUsername,
  assertMnemonic,
} from "./utils/validation";

export {
  getW3pkBuildHash,
  getCurrentBuildHash,
  verifyBuildHash,
  getPackageVersion,
} from "./utils/build-hash";

export type {
  BackupStatus,
  SecurityScore,
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
