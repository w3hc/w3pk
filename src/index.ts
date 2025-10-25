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

export default createWeb3Passkey;
