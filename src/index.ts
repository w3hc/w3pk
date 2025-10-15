/**
 * w3pk - Web3 Passkey SDK
 * WebAuthn SDK for passwordless authentication and encrypted wallet management
 */

import { Web3Passkey } from "./core/sdk";
import type { Web3PasskeyConfig } from "./core/config";

// Main factory function
export function createWeb3Passkey(config: Web3PasskeyConfig): Web3Passkey {
  return new Web3Passkey(config);
}

// Export types
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
export { canControlStealthAddress } from "./stealth/crypto";

// Export wallet generation utilities
export {
  generateBIP39Wallet,
  createWalletFromMnemonic,
  deriveWalletFromMnemonic,
} from "./wallet/generate";

// Default export
export default createWeb3Passkey;
