import { Web3Passkey } from "./core/sdk";
import type { Web3PasskeyConfig } from "./core/config";

export function createWeb3Passkey(config: Web3PasskeyConfig = {}): Web3Passkey {
  return new Web3Passkey(config);
}

export type {
  Web3PasskeyConfig,
  StealthAddressConfig,
  ZKProofConfig,
} from "./core/config";
export type { ZKMethods } from "./core/sdk";
export type {
  EIP1193ProviderInterface,
  ProviderConnectInfo,
  ProviderMessage,
  ProviderRpcError,
} from "./core/eip1193";
export type {
  UserInfo,
  GeneratedWallet,
  DerivedWallet,
  RegisterResult,
  SecurityMode,
  SigningMethod,
  SignMessageOptions,
} from "./types";
export type { PersistentSessionConfig } from "./core/persistent-session";
export type {
  StealthKeys,
  StealthAddressResult,
  Announcement,
  ParseAnnouncementResult,
} from "./stealth";
export type {
  EIP7702Authorization,
  SignAuthorizationParams,
} from "./wallet/types";

export {
  Web3PasskeyError,
  AuthenticationError,
  RegistrationError,
  WalletError,
  CryptoError,
  StorageError,
  ApiError,
  SyncRequiredError,
  WalletMissingError,
  SyncBootstrapError,
  PrfUnsupportedError,
  AddressChangeError,
  RemovedBackupMethodError,
  UnsupportedBackupVersionError,
  WeakPasswordError,
  ZkArtifactMismatchError,
} from "./core/errors";

export type { SyncBootstrapReason, ZkArtifactName } from "./core/errors";

export {
  promptPasskeySelection,
  authenticateWithPasskey,
} from "./auth/sync-auth";
export type { PasskeySelectionResult } from "./auth/sync-auth";
export type { PrfSecret } from "./auth/prf";
export type { SemaphoreIdentity } from "./zk/semaphore";
export type {
  Groth16Proof,
  ZkDerivationTerm,
  ZkInputs,
  ZkProveArtifacts,
  ZkProveOptions,
  ZkProveResult,
  ZkSecretSource,
  ZkSignal,
} from "./zk/prove";
export type {
  ProofType,
  ZKProof,
  VerificationResult,
  MembershipProofInput,
  ThresholdProofInput,
  RangeProofInput,
  OwnershipProofInput,
  NFTOwnershipProofInput,
  CircuitArtifacts,
} from "./zk/types";

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
  BackupMethod,
  SecurityScore,
  RecoveryScenario,
  SimulationResult,
  EncryptedBackupInfo,
} from "./backup/types";

export type { GuardianShare } from "./recovery/backup-based-recovery";
export type { SyncCapabilities } from "./sync/types";
export type { DeviceSyncInfo } from "./sync/backup-sync";

export {
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
export type { Chain, ChainlistOptions } from "./chainlist";

export {
  mlkemEncrypt,
  mlkemDecrypt,
  mlkemEncryptWithKey,
  mlkemDecryptWithKey,
  deriveMLKemKeypair,
  MLKEM_DEFAULT_CONTEXT,
  type EncryptedPayload,
  type MLKemKeypair,
} from "./crypto/mlkem";

export default createWeb3Passkey;
