import type { UserInfo } from "../types";
import type { Web3PasskeyError } from "./errors";
import type { PersistentSessionConfig } from "./persistent-session";

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

  /**
   * Persistent session configuration ("Remember Me" functionality)
   *
   * When enabled, sessions persist across page refreshes for STANDARD and YOLO modes.
   * STRICT mode sessions are NEVER persisted regardless of this setting.
   *
   * Default configuration (secure):
   * - enabled: false (must opt-in)
   * - duration: 168 hours (7 days)
   * - requireReauth: true (prompt on page refresh)
   *
   * @example
   * // Enable "Remember Me" with default settings (7 days, requires reauth)
   * persistentSession: { enabled: true }
   *
   * @example
   * // Full "Remember Me" experience (30 days, auto-restore)
   * persistentSession: {
   *   enabled: true,
   *   duration: 30 * 24,
   *   requireReauth: false
   * }
   */
  persistentSession?: Partial<PersistentSessionConfig>;

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
  persistentSession: {
    enabled: false,
    duration: 168, // 7 days in hours
    requireReauth: true,
  },
  onError: (error: Web3PasskeyError) => {
    if (DEFAULT_CONFIG.debug) {
      console.error("[w3pk]", error);
    }
  },
};
