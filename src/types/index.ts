/**
 * Shared types used across the SDK
 */

export interface UserInfo {
  id: string;
  username: string;
  displayName: string;
  ethereumAddress: string;
}

export interface WalletInfo {
  address: string;
  mnemonic: string;
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
