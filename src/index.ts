import { Web3Passkey } from "./core/sdk";
import type { Web3PasskeyConfig } from "./core/config";

export function createWeb3Passkey(config: Web3PasskeyConfig = {}): Web3Passkey {
  return new Web3Passkey(config);
}

export type { Web3PasskeyConfig, StealthAddressConfig } from "./core/config";
export type { UserInfo, WalletInfo } from "./types";
export type { StealthKeys, StealthAddressResult } from "./stealth";
export type {
  EIP7702Authorization,
  SignAuthorizationParams,
} from "./wallet/types";
export type { EIP1193Provider } from "./eip7702";

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
  DEFAULT_MODE,
  getOriginSpecificAddress,
  deriveIndexFromOriginModeAndTag,
  deriveAddressFromP256PublicKey,
} from "./wallet/origin-derivation";

export {
  RecoverySimulator,
  getExplainer,
  getAllTopics,
  searchExplainers,
} from "./education";

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

export {
  base64UrlToArrayBuffer,
  base64UrlDecode,
  arrayBufferToBase64Url,
  base64ToArrayBuffer,
  safeAtob,
  safeBtoa,
} from "./utils/base64";

export { extractRS } from "./utils/crypto";

export {
  generateBIP39Wallet,
  createWalletFromMnemonic,
  deriveWalletFromMnemonic,
} from "./wallet/generate";

export {
  deriveStealthKeys,
  generateStealthAddress,
  checkStealthAddress,
  computeStealthPrivateKey,
  canControlStealthAddress,
} from "./stealth/crypto";

export {
  generateSiweNonce,
  createSiweMessage,
  parseSiweMessage,
  validateSiweMessage,
  verifySiweSignature,
} from "./siwe";

export type { SiweMessage } from "./siwe";

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

export {
  requestExternalWalletAuthorization,
  getDefaultProvider,
  detectWalletProvider,
  supportsEIP7702Authorization,
  encodeEIP7702AuthorizationMessage,
  hashEIP7702AuthorizationMessage,
  verifyEIP7702Authorization,
} from "./eip7702";

export {
  getEndpoints,
  getAllChains,
  getChainById,
  clearCache,
} from "./chainlist";

export default createWeb3Passkey;
