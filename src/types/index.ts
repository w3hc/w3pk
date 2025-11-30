/**
 * Shared types used across the SDK
 */

export interface UserInfo {
  id: string;
  username: string;
  displayName: string;
  ethereumAddress: string;
  credentialId: string;
}

/**
 * Security modes for origin-centric derivation
 *
 * PRIMARY:
 * - Uses WebAuthn P-256 public key directly (EIP-7951)
 * - No private key (transactions signed via WebAuthn)
 * - Address derived from P-256 public key coordinates
 *
 * STANDARD:
 * - App does NOT have access to private key
 * - Persistent sessions allowed
 *
 * STRICT:
 * - App does NOT have access to private key
 * - Persistent sessions NOT allowed
 *
 * YOLO:
 * - App CAN use private key
 * - Persistent sessions allowed
 */
export type SecurityMode = 'PRIMARY' | 'STANDARD' | 'STRICT' | 'YOLO';

/**
 * Wallet information returned by SDK methods
 *
 * SECURITY GUARANTEES:
 * - `mnemonic` is ONLY included during wallet generation (generateWallet())
 *   and is NEVER exposed through any other SDK method
 * - `privateKey` is conditionally included based on security mode:
 *   - STANDARD mode: Address only (no private key), persistent sessions allowed
 *   - STRICT mode: Address only (no private key), no persistent sessions
 *   - YOLO mode: Full access (address + private key), persistent sessions allowed
 * - Applications CANNOT access the master mnemonic
 * - This ensures apps can only access keys based on the security mode
 */
export interface WalletInfo {
  address: string;
  mnemonic?: string;
  privateKey?: string;
}

export interface ApiResponse<T = any> {
  success: boolean;
  message?: string;
  data?: T;
}

export interface WebAuthnError extends Error {
  code: string;
  originalError?: unknown;
}
