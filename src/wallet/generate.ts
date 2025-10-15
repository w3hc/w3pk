/**
 * BIP39 wallet generation
 */

import { ethers } from "ethers";
import { WalletError } from "../core/errors";
import type { WalletData } from "./types";

/**
 * Generates a new BIP39 wallet with HD derivation
 * Uses BIP44 path: m/44'/60'/0'/0/0 for Ethereum
 */
export function generateBIP39Wallet(): WalletData {
  try {
    // Generate random mnemonic using ethers' utility
    const mnemonic = ethers.Wallet.createRandom().mnemonic;

    if (!mnemonic) {
      throw new Error("Failed to generate mnemonic");
    }

    const mnemonicPhrase = mnemonic.phrase;

    // Create HD wallet from mnemonic phrase with derivation path
    const derivationPath = "m/44'/60'/0'/0/0";
    const hdWallet = ethers.HDNodeWallet.fromPhrase(
      mnemonicPhrase,
      undefined,
      derivationPath
    );

    return {
      address: hdWallet.address,
      mnemonic: mnemonicPhrase,
    };
  } catch (error) {
    throw new WalletError("Wallet generation failed", error);
  }
}

/**
 * Creates wallet from mnemonic phrase
 * Uses BIP44 path: m/44'/60'/0'/0/0
 */
export function createWalletFromMnemonic(
  mnemonic: string
): ethers.HDNodeWallet {
  try {
    if (!mnemonic || mnemonic.trim().split(/\s+/).length < 12) {
      throw new Error("Invalid mnemonic: must be at least 12 words");
    }

    // Create HD wallet with derivation path directly
    const derivationPath = "m/44'/60'/0'/0/0";
    const wallet = ethers.HDNodeWallet.fromPhrase(
      mnemonic.trim(),
      undefined,
      derivationPath
    );

    return wallet;
  } catch (error) {
    throw new WalletError(
      `Wallet creation failed: ${
        error instanceof Error ? error.message : "Invalid mnemonic"
      }`,
      error
    );
  }
}

/**
 * Derives HD wallet address and private key at specific index
 * Uses BIP44 path: m/44'/60'/0'/0/{index}
 */
export function deriveWalletFromMnemonic(
  mnemonic: string,
  index: number = 0
): { address: string; privateKey: string } {
  try {
    if (!mnemonic || mnemonic.trim().split(/\s+/).length < 12) {
      throw new Error("Invalid mnemonic: must be at least 12 words");
    }

    if (index < 0 || !Number.isInteger(index)) {
      throw new Error("Index must be a non-negative integer");
    }

    // Create HD wallet with derivation path including index
    const derivationPath = `m/44'/60'/0'/0/${index}`;
    const wallet = ethers.HDNodeWallet.fromPhrase(
      mnemonic.trim(),
      undefined,
      derivationPath
    );

    return {
      address: wallet.address,
      privateKey: wallet.privateKey,
    };
  } catch (error) {
    throw new WalletError(
      `HD wallet derivation failed: ${
        error instanceof Error ? error.message : "Unknown error"
      }`,
      error
    );
  }
}
