/**
 * SDK Configuration
 */

import type { UserInfo } from "../types";
import type { Web3PasskeyError } from "./errors";
import type { ZKProofConfig } from "../zk/types";

export interface StealthAddressConfig {}

export interface Web3PasskeyConfig {
  /**
   * Base URL of the WebAuthn API
   * @example 'https://webauthn.w3hc.org'
   */
  apiBaseUrl: string;

  /**
   * Timeout for API requests in milliseconds
   * @default 30000
   */
  timeout?: number;

  /**
   * Enable debug logging
   * @default false
   */
  debug?: boolean;

  /**
   * Custom error handler
   */
  onError?: (error: Web3PasskeyError) => void;

  /**
   * Auth state change callback
   */
  onAuthStateChanged?: (isAuthenticated: boolean, user?: UserInfo) => void;

  /**
   * Optional stealth address configuration
   * If provided, enables privacy-preserving stealth address generation
   */
  stealthAddresses?: StealthAddressConfig;

  /**
   * Optional zero-knowledge proof configuration
   * If provided, enables privacy-preserving ZK proofs
   * Requires optional dependencies: snarkjs, circomlibjs
   */
  zkProofs?: ZKProofConfig;
}

export interface InternalConfig extends Required<Web3PasskeyConfig> {
  // Normalized config with all defaults applied
}

export const DEFAULT_CONFIG: Partial<Web3PasskeyConfig> = {
  timeout: 30000,
  debug: false,
};

// Re-export ZK config type
export type { ZKProofConfig } from "../zk/types";
