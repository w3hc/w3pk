/**
 * Message signing with encrypted wallet
 */

import { WalletError } from "../core/errors";
import { createWalletFromMnemonic } from "./generate";
import { deriveEncryptionKey, decryptData } from "./crypto";
import type { IndexedDBWalletStorage } from "./storage";
import type { EIP7702Authorization, SignAuthorizationParams } from "./types";
import { keccak256, concat, toBeHex, Signature, encodeRlp } from "ethers";

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
   * Sign an EIP-7702 authorization
   * Requires fresh WebAuthn authentication
   */
  async signAuthorization(
    ethereumAddress: string,
    params: SignAuthorizationParams,
    credentialId: string,
    challenge: string
  ): Promise<EIP7702Authorization> {
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

      // Get chain ID (default to current chain or 1 for mainnet)
      const chainId = BigInt(params.chainId || 1);

      // Get nonce (default to 0)
      const nonce = params.nonce || 0n;

      // Construct EIP-7702 authorization message
      // Format: 0x05 || rlp([chain_id, address, nonce])
      // Following EIP-7702 spec: use RLP encoding
      const authTuple = [
        chainId === 0n ? "0x" : toBeHex(chainId),
        params.contractAddress.toLowerCase(),
        nonce === 0n ? "0x" : toBeHex(nonce),
      ];

      // RLP encode the authorization tuple
      const rlpEncoded = encodeRlp(authTuple);

      // Concatenate magic byte with RLP encoded data
      const authorizationMessage = concat(["0x05", rlpEncoded]);

      // Hash the authorization message
      const messageHash = keccak256(authorizationMessage);

      // Sign the message hash
      const signature = wallet.signingKey.sign(messageHash);

      // Parse signature into components
      const sig = Signature.from(signature);

      // Return EIP-7702 authorization object
      return {
        chainId,
        address: ethereumAddress.toLowerCase(),
        nonce,
        yParity: sig.yParity,
        r: sig.r,
        s: sig.s
      };
    } catch (error) {
      throw new WalletError("Failed to sign authorization", error);
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
