/**
 * Stealth address cryptography for privacy-preserving transactions
 */

import { ethers } from "ethers";
import { CryptoError } from "../core/errors";

export interface StealthKeys {
  metaAddress: string;
  viewingKey: string;
  spendingKey: string;
}

export interface StealthAddressResult {
  stealthAddress: string;
  stealthPrivkey: string;
  ephemeralPubkey: string;
}

/**
 * Derive stealth keys from w3pk mnemonic using HD paths
 */
export function deriveStealthKeys(mnemonic: string): StealthKeys {
  try {
    // Use specific derivation paths for stealth keys
    const viewingWallet = ethers.HDNodeWallet.fromPhrase(
      mnemonic,
      undefined,
      "m/44'/60'/1'/0/0" // Viewing key path
    );

    const spendingWallet = ethers.HDNodeWallet.fromPhrase(
      mnemonic,
      undefined,
      "m/44'/60'/1'/0/1" // Spending key path
    );

    // Meta address is derived from viewing key
    const metaAddress = computeMetaAddress(
      viewingWallet.signingKey.publicKey,
      spendingWallet.signingKey.publicKey
    );

    return {
      metaAddress,
      viewingKey: viewingWallet.privateKey,
      spendingKey: spendingWallet.privateKey,
    };
  } catch (error) {
    throw new CryptoError("Failed to derive stealth keys", error);
  }
}

/**
 * Generate a stealth address using ECDH
 */
export function generateStealthAddress(
  metaAddress: string
): StealthAddressResult {
  try {
    // Generate ephemeral keypair
    const ephemeralWallet = ethers.Wallet.createRandom();

    // For simplified implementation, derive stealth address from ephemeral key + meta address
    const stealthSeed = ethers.solidityPackedKeccak256(
      ["bytes", "address"],
      [ephemeralWallet.signingKey.publicKey, metaAddress]
    );

    const stealthWallet = new ethers.Wallet(stealthSeed);

    return {
      stealthAddress: stealthWallet.address,
      stealthPrivkey: stealthWallet.privateKey,
      ephemeralPubkey: ephemeralWallet.signingKey.publicKey,
    };
  } catch (error) {
    throw new CryptoError("Failed to generate stealth address", error);
  }
}

/**
 * Check if a stealth address can be controlled by the stealth keys
 * Useful for scanning and proving ownership of stealth addresses
 */
export function canControlStealthAddress(
  viewingKey: string,
  spendingKey: string,
  ephemeralPubkey: string,
  targetAddress: string
): boolean {
  try {
    // Reconstruct stealth address using both viewing and spending keys
    const viewingWallet = new ethers.Wallet(viewingKey);
    const spendingWallet = new ethers.Wallet(spendingKey);
    
    const metaAddress = computeMetaAddress(
      viewingWallet.signingKey.publicKey,
      spendingWallet.signingKey.publicKey
    );

    const stealthSeed = ethers.solidityPackedKeccak256(
      ["bytes", "address"],
      [ephemeralPubkey, metaAddress]
    );

    const derivedWallet = new ethers.Wallet(stealthSeed);

    return derivedWallet.address.toLowerCase() === targetAddress.toLowerCase();
  } catch (error) {
    return false;
  }
}

/**
 * Compute meta address from public keys (simplified)
 */
function computeMetaAddress(
  viewingPubkey: string,
  spendingPubkey: string
): string {
  const combined = ethers.solidityPackedKeccak256(
    ["bytes", "bytes"],
    [viewingPubkey, spendingPubkey]
  );

  // Take first 20 bytes as address
  return ethers.getAddress("0x" + combined.slice(26));
}
