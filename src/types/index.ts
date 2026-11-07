/**
 * Shared types used across the SDK
 */

import type { TypedDataDomain } from "ethers";

export interface UserInfo {
  username: string;
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
 * - Always requires a fresh user-verified passkey assertion: the hash could be
 *   an EIP-7702 authorization digest
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
  signingMethod?: SigningMethod;
  // EIP-712 specific options (only used when signingMethod === 'EIP712')
  eip712Domain?: TypedDataDomain;
  eip712Types?: Record<string, Array<{ name: string; type: string }>>;
  eip712PrimaryType?: string;
  /** PRIMARY mode: chain the signature is bound to; required for EIP191, read from the message for SIWE and from eip712Domain for EIP712 */
  chainId?: number;
  /** PRIMARY mode: RPC endpoint used to check whether the account is deployed (default: rpcUrls[chainId][0]) */
  rpcUrl?: string;
}

/**
 * Result of register()
 */
export interface RegisterResult {
  address: string;
  username: string;
  hasBackup: boolean;
  evictionRisk: boolean;
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
  path?: string;
  origin?: string;
  mode?: SecurityMode;
  tag?: string;
  publicKey?: string;
}

/**
 * A transaction for sendTransaction()
 */
export interface TransactionRequest {
  to: string;
  value?: bigint;
  data?: string;
  chainId: number;
  /** Ignored in PRIMARY mode: the bundler estimates the UserOperation's gas */
  gasLimit?: bigint;
  maxFeePerGas?: bigint;
  maxPriorityFeePerGas?: bigint;
  /** Ignored in PRIMARY mode: the EntryPoint sets the UserOperation's nonce */
  nonce?: number;
}

/**
 * Options for sendTransaction()
 */
export interface SendTransactionOptions {
  mode?: SecurityMode;
  tag?: string;
  requireAuth?: boolean;
  /** Chain RPC endpoint (default: rpcUrls[chainId][0]) */
  rpcUrl?: string;
  /** PRIMARY mode: ERC-4337 bundler endpoint (default: bundlerUrls[chainId]) */
  bundlerUrl?: string;
  /** PRIMARY mode: ERC-7677 paymaster service (default: paymasterUrl from the config) */
  paymasterUrl?: string;
  /** PRIMARY mode: ERC-7677 `context` sent to the paymaster service (default: {}) */
  paymasterContext?: Record<string, unknown>;
  /** PRIMARY mode: how long to wait for the UserOperation's inclusion, in ms (default: 60000) */
  timeout?: number;
}

/**
 * Result of sendTransaction()
 */
export interface SendTransactionResult {
  /** Hash of the transaction, in PRIMARY mode of the bundle transaction that included the UserOperation */
  hash: string;
  from: string;
  chainId: number;
  mode: SecurityMode;
  tag: string;
  origin: string;
  /** PRIMARY mode: hash of the UserOperation */
  userOpHash?: string;
}
