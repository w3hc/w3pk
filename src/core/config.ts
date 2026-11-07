import type { UserInfo } from "../types";
import type { Web3PasskeyError } from "./errors";
import type { PersistentSessionConfig } from "./persistent-session";
import type { ZKProofConfig } from "../zk/types";
import type { SmartAccountConfig } from "../wallet/smart-account";

export interface StealthAddressConfig {}

export type { ZKProofConfig };

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

  /**
   * WebAuthn user verification for login, registration and signing
   * (default: 'required'). With 'preferred', authenticators that can skip
   * the biometric/PIN check (security keys, unlocked password managers)
   * sign in with one click. PRF-derived secrets always require it.
   */
  userVerification?: 'required' | 'preferred';

  /**
   * RPC endpoints per chain ID. `sendTransaction()` uses the first one and
   * throws for a chain with none (a per-call `rpcUrl` takes precedence);
   * `getEndpoints()` and `supportsEIP7702()` list them before the
   * chainid.network endpoints.
   *
   * @example
   * rpcUrls: { 1: ['https://eth.example.com'], 10: ['https://op.example.com'] }
   */
  rpcUrls?: Record<number, string[]>;

  /**
   * ERC-4337 bundler endpoint per chain ID, for `sendTransaction()` in
   * `PRIMARY` mode (a per-call `bundlerUrl` takes precedence). The bundler
   * must support EntryPoint v0.9.
   *
   * @example
   * bundlerUrls: { 10: 'https://bundler.example/optimism' }
   */
  bundlerUrls?: Record<number, string>;

  /**
   * ERC-7677 paymaster service that sponsors `PRIMARY` mode transactions (a
   * per-call `paymasterUrl` takes precedence). Without one, the smart account
   * pays its own gas.
   */
  paymasterUrl?: string;

  /**
   * `PRIMARY` mode smart account factory (default: `W3PK_ACCOUNT_FACTORY`)
   * and clone init code hash (default: `W3PK_ACCOUNT_INIT_CODE_HASH`), for a
   * factory deployed elsewhere
   */
  smartAccount?: SmartAccountConfig;
}

export interface InternalConfig extends Required<Web3PasskeyConfig> {}

export const DEFAULT_CONFIG: Partial<InternalConfig> = {
  debug: false,
  sessionDuration: 1,
  userVerification: 'required',
  rpcUrls: {},
  bundlerUrls: {},
  smartAccount: {},
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
