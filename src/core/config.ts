/**
 * SDK Configuration
 */

import type { UserInfo } from "../types";
import type { Web3PasskeyError } from "./errors";

export interface StealthAddressConfig {}

export interface ZKProofConfig {
  enabledProofs?: Array<
    | "membership"
    | "threshold"
    | "range"
    | "equality"
    | "ownership"
    | "signature"
    | "nft"
  >;
  customCircuits?: Record<string, any>;
}

export interface Web3PasskeyConfig {
  debug?: boolean;
  onError?: (error: Web3PasskeyError) => void;
  onAuthStateChanged?: (isAuthenticated: boolean, user?: UserInfo) => void;
  storage?: Storage;

  /**
   * Session duration in hours
   * After successful authentication, the decrypted mnemonic is cached for this duration
   * This allows operations like deriveWallet(), exportMnemonic(), stealth addresses, etc.
   * to work without repeated authentication prompts
   *
   * @default 1 (hour)
   * Set to 0 to require authentication for every operation (most secure)
   */
  sessionDuration?: number;

  /**
   * Stealth address configuration (ERC-5564)
   */
  stealthAddresses?: StealthAddressConfig;

  /**
   * Zero-knowledge proof configuration
   * Requires: snarkjs, circomlibjs
   */
  zkProofs?: ZKProofConfig;
}

export interface InternalConfig extends Required<Web3PasskeyConfig> {
  // Normalized config with all defaults applied
}

export const DEFAULT_CONFIG: Partial<InternalConfig> = {
  debug: false,
  sessionDuration: 1, // 1 hour default
  onError: (error: Web3PasskeyError) => {
    if (DEFAULT_CONFIG.debug) {
      console.error("[w3pk]", error);
    }
  },
};
