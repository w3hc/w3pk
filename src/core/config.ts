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
   * Session duration in hours (default: 1)
   * Set to 0 to require authentication for every operation
   */
  sessionDuration?: number;

  stealthAddresses?: StealthAddressConfig;

  /**
   * Zero-knowledge proof configuration
   * Requires: snarkjs, circomlibjs
   */
  zkProofs?: ZKProofConfig;
}

export interface InternalConfig extends Required<Web3PasskeyConfig> {}

export const DEFAULT_CONFIG: Partial<InternalConfig> = {
  debug: false,
  sessionDuration: 1,
  onError: (error: Web3PasskeyError) => {
    if (DEFAULT_CONFIG.debug) {
      console.error("[w3pk]", error);
    }
  },
};
