/**
 * EIP-7702 Utility Functions
 * Shared encoding logic to ensure consistency across all implementations
 */

import { encodeRlp, concat, keccak256, toBeHex, recoverAddress, Signature } from "ethers";

/**
 * Encode EIP-7702 authorization message
 *
 * @param chainId - Chain ID for the authorization
 * @param contractAddress - Contract address to delegate to
 * @param nonce - Nonce for the authorization
 * @returns Encoded authorization message bytes
 *
 * @spec EIP-7702: 0x05 || rlp([chain_id, address, nonce])
 */
export function encodeEIP7702AuthorizationMessage(
  chainId: bigint,
  contractAddress: string,
  nonce: bigint
): string {
  // Construct tuple according to EIP-7702 spec
  const authTuple = [
    chainId === 0n ? "0x" : toBeHex(chainId),
    contractAddress.toLowerCase(),
    nonce === 0n ? "0x" : toBeHex(nonce),
  ];

  // RLP encode the tuple
  const rlpEncoded = encodeRlp(authTuple);

  // Concatenate magic byte (0x05) with RLP encoded data
  const authorizationMessage = concat(["0x05", rlpEncoded]);

  return authorizationMessage;
}

/**
 * Hash EIP-7702 authorization message
 *
 * @param chainId - Chain ID for the authorization
 * @param contractAddress - Contract address to delegate to
 * @param nonce - Nonce for the authorization
 * @returns Keccak256 hash of the authorization message
 */
export function hashEIP7702AuthorizationMessage(
  chainId: bigint,
  contractAddress: string,
  nonce: bigint
): string {
  const message = encodeEIP7702AuthorizationMessage(chainId, contractAddress, nonce);
  return keccak256(message);
}

/**
 * Verify EIP-7702 authorization signature
 *
 * @param chainId - Chain ID for the authorization
 * @param contractAddress - Contract address being delegated to
 * @param nonce - Nonce for the authorization
 * @param signature - The signature components (yParity, r, s) or hex string
 * @param expectedSigner - The expected signer address
 * @returns true if signature is valid and from expected signer
 *
 * @example
 * ```typescript
 * const isValid = verifyEIP7702Authorization(
 *   1n,
 *   "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1",
 *   0n,
 *   { yParity: 1, r: "0x...", s: "0x..." },
 *   "0x1234567890123456789012345678901234567890"
 * );
 * ```
 */
export function verifyEIP7702Authorization(
  chainId: bigint,
  contractAddress: string,
  nonce: bigint,
  signature: { yParity: number; r: string; s: string } | string,
  expectedSigner: string
): boolean {
  try {
    const messageHash = hashEIP7702AuthorizationMessage(chainId, contractAddress, nonce);

    // Convert signature to proper format if needed
    let sig: any;
    if (typeof signature === 'string') {
      sig = Signature.from(signature);
    } else {
      sig = signature;
    }

    const recoveredAddress = recoverAddress(messageHash, sig);

    return recoveredAddress.toLowerCase() === expectedSigner.toLowerCase();
  } catch (error) {
    return false;
  }
}
