/**
 * External Wallet EIP-7702 Authorization Utilities
 *
 * This module provides utilities for users to sign EIP-7702 authorizations
 * using external wallets (MetaMask, Rabby, hardware wallets, etc.) to delegate
 * their external wallet accounts to W3PK accounts.
 *
 * Use cases:
 * - Delegate ENS-linked addresses to W3PK for gasless transactions
 * - Integrate hardware wallets for enhanced security
 * - Enable multi-signature setups combining external and W3PK accounts
 * - Migrate existing wallet users to W3PK while maintaining their addresses
 *
 * Flow:
 * 1. User has an external wallet account (MetaMask, Ledger, etc.)
 * 2. User creates or has a W3PK account
 * 3. User signs EIP-7702 authorization delegating external account to W3PK account
 * 4. User includes authorization in transaction to activate delegation
 */

import type { EIP7702Authorization } from "../wallet/types";

/**
 * EIP-1193 Provider interface (MetaMask, Rabby, etc.)
 */
export interface EIP1193Provider {
  request(args: { method: string; params?: any[] }): Promise<any>;
  on?(event: string, handler: (...args: any[]) => void): void;
  removeListener?(event: string, handler: (...args: any[]) => void): void;
}

/**
 * Request user to sign EIP-7702 authorization with external wallet
 *
 * @param provider - EIP-1193 provider (window.ethereum)
 * @param params - Authorization parameters
 * @param params.delegateToAddress - The w3pk account address to delegate to
 * @param params.chainId - Chain ID for the authorization
 * @param params.nonce - Nonce (default: 0n)
 * @param params.accountIndex - Optional: request specific account from wallet (default: 0)
 * @returns EIP-7702 authorization object
 *
 * @example
 * ```typescript
 * import { requestExternalWalletAuthorization } from 'w3pk';
 *
 * // Get user's w3pk account
 * const w3pkAddress = w3pk.getAddress();
 *
 * // Request MetaMask to sign authorization
 * const authorization = await requestExternalWalletAuthorization(
 *   window.ethereum,
 *   {
 *     delegateToAddress: w3pkAddress,
 *     chainId: 1,
 *     nonce: 0n
 *   }
 * );
 *
 * // Use in transaction
 * await provider.request({
 *   method: 'eth_sendTransaction',
 *   params: [{
 *     to: someContract,
 *     data: txData,
 *     authorizationList: [authorization]
 *   }]
 * });
 * ```
 */
export async function requestExternalWalletAuthorization(
  provider: EIP1193Provider,
  params: {
    delegateToAddress: string;
    chainId?: number;
    nonce?: bigint;
    accountIndex?: number;
  }
): Promise<EIP7702Authorization> {
  if (!provider) {
    throw new Error("No external wallet provider found. Please install MetaMask or similar wallet.");
  }

  const chainId = BigInt(params.chainId || 1);
  const nonce = params.nonce || 0n;
  const accountIndex = params.accountIndex || 0;

  // Get user's accounts from external wallet
  const accounts = await provider.request({
    method: "eth_requestAccounts",
  }) as string[];

  if (!accounts || accounts.length === 0) {
    throw new Error("No accounts found in external wallet");
  }

  if (accountIndex >= accounts.length) {
    throw new Error(`Account index ${accountIndex} out of range. Wallet has ${accounts.length} accounts.`);
  }

  const signerAddress = accounts[accountIndex];

  // Hash EIP-7702 authorization message using shared utility
  const { hashEIP7702AuthorizationMessage, verifyEIP7702Authorization } = await import("./utils");
  const { Signature } = await import("ethers");

  const messageHash = hashEIP7702AuthorizationMessage(
    chainId,
    params.delegateToAddress,
    nonce
  );

  // Request signature from external wallet using personal_sign
  // Note: Some wallets may not support eth_signTransaction with EIP-7702 yet,
  // so we use personal_sign and then parse the signature
  let signatureHex: string;

  try {
    // Try eth_sign first (standard method for raw message signing)
    signatureHex = await provider.request({
      method: "eth_sign",
      params: [signerAddress, messageHash],
    }) as string;
  } catch (error) {
    // Fallback to personal_sign if eth_sign is disabled
    try {
      signatureHex = await provider.request({
        method: "personal_sign",
        params: [messageHash, signerAddress],
      }) as string;
    } catch (personalSignError) {
      throw new Error(
        `Failed to request signature from wallet. ` +
        `eth_sign error: ${(error as Error).message}, ` +
        `personal_sign error: ${(personalSignError as Error).message}`
      );
    }
  }

  // Parse signature into components
  const sig = Signature.from(signatureHex);

  // Build authorization object
  const authorization = {
    chainId,
    address: params.delegateToAddress.toLowerCase(),
    nonce,
    yParity: sig.yParity,
    r: sig.r,
    s: sig.s,
  };

  // Verify signature matches expected signer
  const isValid = verifyEIP7702Authorization(
    chainId,
    params.delegateToAddress,
    nonce,
    authorization,
    signerAddress
  );

  if (!isValid) {
    throw new Error(
      `Signature verification failed. Expected signer: ${signerAddress}, ` +
      `but signature does not match. This may indicate a wallet implementation issue.`
    );
  }

  // Return EIP-7702 authorization object
  return authorization;
}

/**
 * Get the default Ethereum provider (window.ethereum)
 * Handles multiple injected wallets and provider detection
 *
 * @returns EIP-1193 provider or null if not found
 */
export function getDefaultProvider(): EIP1193Provider | null {
  if (typeof window === "undefined") {
    return null;
  }

  const win = window as any;

  // Check for ethereum provider
  if (win.ethereum) {
    // If multiple providers (e.g., MetaMask + Rabby), use the default
    return win.ethereum;
  }

  // Check for specific providers as fallback
  if (win.web3?.currentProvider) {
    return win.web3.currentProvider;
  }

  return null;
}

/**
 * Detect which wallet provider is being used
 *
 * @param provider - EIP-1193 provider
 * @returns Wallet name or 'Unknown'
 */
export function detectWalletProvider(provider: EIP1193Provider): string {
  const p = provider as any;

  if (p.isMetaMask) return "MetaMask";
  if (p.isRabby) return "Rabby";
  if (p.isCoinbaseWallet) return "Coinbase Wallet";
  if (p.isBraveWallet) return "Brave Wallet";
  if (p.isTokenPocket) return "TokenPocket";
  if (p.isTrust) return "Trust Wallet";

  return "Unknown Wallet";
}

/**
 * Check if a provider supports EIP-7702
 * Note: This is a best-effort check as EIP-7702 support is still rolling out
 *
 * @param provider - EIP-1193 provider
 * @returns true if provider likely supports EIP-7702
 */
export async function supportsEIP7702Authorization(
  provider: EIP1193Provider
): Promise<boolean> {
  try {
    // Check if provider supports eth_sign or personal_sign
    // This is a minimal check - actual EIP-7702 support depends on the RPC node
    const accounts = await provider.request({
      method: "eth_accounts",
    });

    return Array.isArray(accounts);
  } catch {
    return false;
  }
}
