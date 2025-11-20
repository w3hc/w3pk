/**
 * Shared types used across the SDK
 */

export interface UserInfo {
  id: string;
  username: string;
  displayName: string;
  ethereumAddress: string;
}

/**
 * Wallet information returned by SDK methods
 *
 * SECURITY GUARANTEES:
 * - `mnemonic` is ONLY included during wallet generation (generateWallet())
 *   and is NEVER exposed through any other SDK method
 * - `privateKey` is conditionally included based on derivation method:
 *   - NEVER exposed for MAIN tag origin-specific derivation (e.g., deriveWallet())
 *   - ONLY exposed for non-MAIN tag derivation (e.g., deriveWallet('GAMING'))
 * - Applications CANNOT access the master mnemonic or private keys except through
 *   origin-specific derived wallets with non-MAIN tags
 * - This ensures apps can only access keys specifically intended for their origin
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
