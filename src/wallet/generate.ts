import { ethers } from "ethers";
import { WalletError } from "../core/errors";
import type { WalletData } from "./types";

/**
 * Generate BIP39 wallet with HD derivation
 * Uses BIP44 path: m/44'/60'/0'/0/0
 */
export function generateBIP39Wallet(): WalletData {
  try {
    const mnemonic = ethers.Wallet.createRandom().mnemonic;

    if (!mnemonic) {
      throw new Error("Failed to generate mnemonic");
    }

    const mnemonicPhrase = mnemonic.phrase;
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
 * Create wallet from mnemonic
 * Uses BIP44 path: m/44'/60'/0'/0/0
 */
export function createWalletFromMnemonic(
  mnemonic: string
): ethers.HDNodeWallet {
  try {
    if (!mnemonic || mnemonic.trim().split(/\s+/).length < 12) {
      throw new Error("Invalid mnemonic: must be at least 12 words");
    }

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
 * Derive HD wallet at specific index
 * Uses BIP44 path: m/44'/60'/0'/0/{index}
 */
export function deriveWalletFromMnemonic(
  mnemonic: string,
  index: number = 0
): { address: string; privateKey: string } {
  if (index < 0 || !Number.isInteger(index)) {
    throw new WalletError(
      "HD wallet derivation failed: Index must be a non-negative integer"
    );
  }

  return deriveWalletFromPath(mnemonic, `m/44'/60'/0'/0/${index}`);
}

/**
 * Derive HD wallet at a full BIP-32 path from the mnemonic's root
 */
export function deriveWalletFromPath(
  mnemonic: string,
  path: string
): { address: string; privateKey: string } {
  try {
    if (!mnemonic || mnemonic.trim().split(/\s+/).length < 12) {
      throw new Error("Invalid mnemonic: must be at least 12 words");
    }

    const wallet = ethers.HDNodeWallet.fromPhrase(
      mnemonic.trim(),
      undefined,
      path
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
