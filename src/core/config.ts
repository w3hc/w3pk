/**
 * SDK Configuration
 */

import type { UserInfo } from "../types";
import type { Web3PasskeyError } from "./errors";

export interface StealthAddressConfig {
  // Stealth address configuration options
}

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
   *
   * ⚠️ Requires additional dependencies (adds ~70MB to bundle):
   * ```bash
   * npm install snarkjs circomlibjs
   * ```
   *
   * If provided, enables privacy-preserving ZK proofs:
   * - Membership proofs (anonymous set membership)
   * - Threshold proofs (prove value > threshold)
   * - Range proofs (prove value in range)
   * - NFT ownership proofs (anonymous NFT ownership)
   *
   * @see https://github.com/w3hc/w3pk/blob/main/docs/ZK_INTEGRATION_GUIDE.md
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

// ZK config type defined inline to avoid importing from ZK modules
export interface ZKProofConfig {
  enabledProofs?: string[];
  circuitArtifacts?: Record<string, any>;
  [key: string]: any;
}
