/**
 * Shared types used across the SDK
 */

export interface UserInfo {
  username: string;
  ethereumAddress: string;
  credentialId: string;
  /** @deprecated Use ethereumAddress instead */
  id?: string;
  /** @deprecated Use username instead */
  displayName?: string;
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
 * Signing methods for message signatures
 *
 * EIP191 (default):
 * - Standard Ethereum signed message with prefix
 * - Message prefixed with "\x19Ethereum Signed Message:\n<length>"
 * - Suitable for general message signing
 *
 * SIWE:
 * - Sign-In with Ethereum (EIP-4361) compliant
 * - Message should be a properly formatted SIWE message
 * - Signed with EIP-191 prefix (for EOA accounts)
 *
 * EIP712:
 * - Sign structured typed data (EIP-712)
 * - Automatically computes domain separator and struct hash
 * - Requires domain, types, primaryType, and message in options
 *
 * rawHash:
 * - Sign raw 32-byte hashes without EIP-191 prefix
 * - Useful for pre-computed EIP-712 hashes or Safe transactions
 * - Message must be a 32-byte hex string (with or without 0x prefix)
 */
export type SigningMethod = 'EIP191' | 'SIWE' | 'EIP712' | 'rawHash';

/**
 * Options for signMessage method
 * EIP-712 specific fields are only used when signingMethod is 'EIP712'
 */
export interface SignMessageOptions {
  mode?: SecurityMode;
  tag?: string;
  requireAuth?: boolean;
  origin?: string;
  signingMethod?: SigningMethod;
  // EIP-712 specific options (only used when signingMethod === 'EIP712')
  eip712Domain?: Record<string, any>;
  eip712Types?: Record<string, Array<{ name: string; type: string }>>;
  eip712PrimaryType?: string;
}

/**
 * Generated wallet with mnemonic (from generateWallet)
 */
export interface GeneratedWallet {
  address: string;
  mnemonic: string;
}

/**
 * Derived wallet from origin-specific derivation
 *
 * SECURITY GUARANTEES:
 * - `privateKey` is conditionally included based on security mode:
 *   - STANDARD mode: Address only (no private key), persistent sessions allowed
 *   - STRICT mode: Address only (no private key), no persistent sessions
 *   - YOLO mode: Full access (address + private key), persistent sessions allowed
 * - Applications CANNOT access the master mnemonic
 * - This ensures apps can only access keys based on the security mode
 */
export interface DerivedWallet {
  address: string;
  privateKey?: string;
  index?: number;
  origin?: string;
  mode?: SecurityMode;
  tag?: string;
  publicKey?: string;
}

/**
 * @deprecated Use GeneratedWallet or DerivedWallet instead
 */
export type WalletInfo = GeneratedWallet | DerivedWallet;

export interface ApiResponse<T = any> {
  success: boolean;
  message?: string;
  data?: T;
}

export interface WebAuthnError extends Error {
  code: string;
  originalError?: unknown;
}
