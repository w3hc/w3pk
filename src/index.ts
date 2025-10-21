/**
 * w3pk - Web3 Passkey SDK
 * WebAuthn SDK for passwordless authentication, encrypted wallet management,
 * and stealth addresses
 *
 * Core features (included):
 * - WebAuthn passwordless authentication
 * - Encrypted wallet management (AES-GCM-256)
 * - BIP39/BIP44 HD wallet generation
 * - Stealth addresses for privacy-preserving transactions
 *
 * Zero-knowledge proofs (optional):
 * - Requires: npm install snarkjs circomlibjs
 * - Import from: 'w3pk/zk' and 'w3pk/zk/utils'
 * - See: https://github.com/w3hc/w3pk#zero-knowledge-proofs
 */

import { Web3Passkey } from "./core/sdk";
import type { Web3PasskeyConfig } from "./core/config";

// Main factory function
export function createWeb3Passkey(config: Web3PasskeyConfig): Web3Passkey {
  return new Web3Passkey(config);
}

// Export core types
export type { Web3PasskeyConfig, StealthAddressConfig } from "./core/config";
export type { UserInfo, WalletInfo } from "./types";
export type { StealthKeys, StealthAddressResult } from "./stealth";

// Export errors for custom error handling
export {
  Web3PasskeyError,
  AuthenticationError,
  RegistrationError,
  WalletError,
  CryptoError,
  StorageError,
  ApiError,
} from "./core/errors";

// Export SDK class for advanced usage
export { Web3Passkey } from "./core/sdk";

// Export stealth address module for advanced usage
export { StealthAddressModule } from "./stealth";

// Export crypto utilities
export {
  canControlStealthAddress,
  generateStealthAddress,
  checkStealthAddress,
  computeStealthPrivateKey,
  deriveStealthKeys
} from "./stealth/crypto";

// Export wallet generation utilities
export {
  generateBIP39Wallet,
  createWalletFromMnemonic,
  deriveWalletFromMnemonic,
} from "./wallet/generate";

/**
 * Zero-Knowledge Proofs
 *
 * ZK features are in separate exports to avoid bundling heavy dependencies
 * for users who don't need them.
 *
 * @requires npm install snarkjs circomlibjs
 *
 * @example
 * ```typescript
 * // Import ZK module
 * import { ZKProofModule } from 'w3pk/zk'
 *
 * // Import ZK utilities
 * import { buildMerkleTree, generateBlinding } from 'w3pk/zk/utils'
 *
 * // Enable in config
 * const w3pk = createWeb3Passkey({
 *   apiBaseUrl: 'https://webauthn.w3hc.org',
 *   zkProofs: {
 *     enabledProofs: ['membership', 'threshold']
 *   }
 * })
 * ```
 *
 * @see https://github.com/w3hc/w3pk/blob/main/docs/ZK_INTEGRATION_GUIDE.md
 */

// Default export
export default createWeb3Passkey;
