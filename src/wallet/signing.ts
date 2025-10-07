/**
 * Message signing with encrypted wallet
 */

import { WalletError } from "../core/errors";
import { createWalletFromMnemonic } from "./generate";
import { deriveEncryptionKey, decryptData } from "./crypto";
import type { IndexedDBWalletStorage } from "./storage";

export class WalletSigner {
  constructor(private storage: IndexedDBWalletStorage) {}

  /**
   * Sign a message with the encrypted wallet
   * Requires fresh WebAuthn authentication
   */
  async signMessage(
    ethereumAddress: string,
    message: string,
    credentialId: string,
    challenge: string
  ): Promise<string> {
    try {
      // Retrieve encrypted wallet data
      const walletData = await this.storage.retrieve(ethereumAddress);
      if (!walletData) {
        throw new Error("No wallet found for this address");
      }

      // Derive encryption key from WebAuthn credentials
      const encryptionKey = await deriveEncryptionKey(credentialId, challenge);

      // Decrypt mnemonic
      const mnemonic = await decryptData(
        walletData.encryptedMnemonic,
        encryptionKey
      );

      // Create wallet from mnemonic
      const wallet = createWalletFromMnemonic(mnemonic);

      // Verify address matches
      if (wallet.address.toLowerCase() !== ethereumAddress.toLowerCase()) {
        throw new Error("Wallet address mismatch");
      }

      // Sign message
      const signature = await wallet.signMessage(message);

      // Clear mnemonic from memory (wallet will be garbage collected)
      return signature;
    } catch (error) {
      throw new WalletError("Failed to sign message", error);
    }
  }

  /**
   * Check if wallet exists for address
   */
  async hasWallet(ethereumAddress: string): Promise<boolean> {
    const walletData = await this.storage.retrieve(ethereumAddress);
    return walletData !== null;
  }
}
