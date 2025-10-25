/**
 * Main Web3Passkey SDK class - Client-Only Version
 * No server required - all authentication happens locally
 */

import { register } from "../auth/register";
import { login } from "../auth/authenticate";
import { IndexedDBWalletStorage } from "../wallet/storage";
import { WalletSigner } from "../wallet/signing";
import {
  generateBIP39Wallet,
  deriveWalletFromMnemonic,
} from "../wallet/generate";
import {
  deriveEncryptionKey,
  encryptData,
  decryptData,
} from "../wallet/crypto";
import { StealthAddressModule } from "../stealth";
// ZK module imported dynamically to avoid bundling dependencies
import type { Web3PasskeyConfig, InternalConfig } from "./config";
import { DEFAULT_CONFIG } from "./config";
import type { UserInfo, WalletInfo } from "../types";
import { AuthenticationError, WalletError } from "./errors";
import { getEndpoints } from "../chainlist";
import { supportsEIP7702 } from "../eip7702";

export class Web3Passkey {
  private config: InternalConfig;
  private walletStorage: IndexedDBWalletStorage;
  private walletSigner: WalletSigner;
  private currentUser: UserInfo | null = null;
  private currentWallet: WalletInfo | null = null;

  // Optional modules
  public stealth?: StealthAddressModule;
  private zkModule?: any;

  constructor(config: Web3PasskeyConfig = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config } as InternalConfig;
    this.walletStorage = new IndexedDBWalletStorage();
    this.walletSigner = new WalletSigner(this.walletStorage);

    // Initialize optional modules
    if (config.stealthAddresses !== undefined) {
      this.stealth = new StealthAddressModule(
        config.stealthAddresses,
        () => this.exportMnemonic()
      );
    }

    // Initialize ZK module if configured
    if (config.zkProofs) {
      this.initializeZKModule(config.zkProofs);
    }
  }

  /**
   * Lazy-load ZK module to avoid bundling large dependencies
   */
  private async initializeZKModule(zkConfig: any) {
    try {
      const { ZKProofModule } = await import("../zk");
      this.zkModule = new ZKProofModule(zkConfig);
    } catch (error) {
      console.warn(
        "ZK module not available. Install dependencies: npm install snarkjs circomlibjs"
      );
    }
  }

  /**
   * Register a new user with WebAuthn
   * Automatically generates a wallet if none exists
   * Creates a passkey and associates it with the Ethereum address (account #0)
   * Returns the mnemonic phrase - IMPORTANT: User must save this!
   */
  async register(options: { username: string }): Promise<{ mnemonic: string }> {
    try {
      // Auto-generate wallet if it doesn't exist
      if (!this.currentWallet?.address) {
        await this.generateWallet();
      }

      // Derive account #0 address from the generated wallet
      const ethereumAddress = this.currentWallet!.address;
      const mnemonic = this.currentWallet!.mnemonic!;

      await register({
        username: options.username,
        ethereumAddress,
      });

      // Update auth state
      this.currentUser = {
        id: ethereumAddress, // Use address as unique ID
        username: options.username,
        displayName: options.username, // Use username as display name
        ethereumAddress,
      };

      // Notify state change
      this.config.onAuthStateChanged?.(true, this.currentUser);

      // Return mnemonic so user can save it
      return { mnemonic };
    } catch (error) {
      this.config.onError?.(error as any);
      throw error;
    }
  }

  /**
   * Login with WebAuthn (usernameless)
   * Uses resident credentials stored in the authenticator
   */
  async login(): Promise<UserInfo> {
    try {
      const result = await login();

      if (!result.verified || !result.user) {
        throw new AuthenticationError("Login failed");
      }

      this.currentUser = {
        id: result.user.ethereumAddress, // Use address as unique ID
        username: result.user.username,
        displayName: result.user.username, // Use username as display name
        ethereumAddress: result.user.ethereumAddress,
      };

      // Notify state change
      this.config.onAuthStateChanged?.(true, this.currentUser);

      return this.currentUser;
    } catch (error) {
      this.config.onError?.(error as any);
      throw error;
    }
  }

  /**
   * Logout the current user
   */
  async logout(): Promise<void> {
    this.currentUser = null;
    this.currentWallet = null;
    this.config.onAuthStateChanged?.(false, undefined);
  }

  /**
   * Get current authentication status
   */
  get isAuthenticated(): boolean {
    return this.currentUser !== null;
  }

  /**
   * Get current user info
   */
  get user(): UserInfo | null {
    return this.currentUser;
  }

  /**
   * Generate a new BIP39 wallet
   * Returns the mnemonic phrase (12 words)
   * After registration/authentication, call saveWallet() to encrypt and store it
   */
  async generateWallet(): Promise<{ mnemonic: string }> {
    try {
      // Generate new BIP39 wallet
      const wallet = generateBIP39Wallet();

      // Store in memory (unencrypted) until user authenticates
      this.currentWallet = {
        address: wallet.address,
        mnemonic: wallet.mnemonic,
      };

      return {
        mnemonic: wallet.mnemonic,
      };
    } catch (error) {
      this.config.onError?.(error as any);
      throw new WalletError("Failed to generate wallet", error);
    }
  }

  /**
   * Save the current wallet (encrypt and store)
   * Must be called after authentication to persist the wallet securely
   */
  async saveWallet(): Promise<void> {
    try {
      if (!this.currentUser) {
        throw new WalletError("Must be authenticated to save wallet");
      }

      if (!this.currentWallet?.mnemonic) {
        throw new WalletError("No wallet to save. Generate a wallet first.");
      }

      // Re-authenticate to get fresh credentials for encryption
      const authResult = await login();
      if (!authResult.user) {
        throw new WalletError("Re-authentication failed");
      }

      const credentialId = authResult.user.credentialId;

      // Generate a challenge for encryption key derivation
      const challenge = this.generateChallenge();

      // Derive encryption key from WebAuthn credentials
      const encryptionKey = await deriveEncryptionKey(credentialId, challenge);

      // Encrypt the mnemonic
      const encryptedMnemonic = await encryptData(
        this.currentWallet.mnemonic,
        encryptionKey
      );

      // Store encrypted wallet
      await this.walletStorage.store({
        ethereumAddress: this.currentUser.ethereumAddress,
        encryptedMnemonic,
        credentialId,
        challenge,
        createdAt: Date.now(),
      });
    } catch (error) {
      this.config.onError?.(error as any);
      throw new WalletError("Failed to save wallet", error);
    }
  }

  /**
   * Derive an HD wallet at a specific index
   */
  async deriveWallet(index: number): Promise<WalletInfo> {
    try {
      if (!this.currentUser) {
        throw new WalletError("Must be authenticated to derive wallet");
      }

      // Get encrypted wallet data
      const walletData = await this.walletStorage.retrieve(
        this.currentUser.ethereumAddress
      );

      if (!walletData) {
        throw new WalletError("No wallet found. Generate a wallet first.");
      }

      // Re-authenticate to decrypt
      const authResult = await login();
      if (!authResult.user) {
        throw new WalletError("Re-authentication failed");
      }

      // Derive encryption key
      const encryptionKey = await deriveEncryptionKey(
        walletData.credentialId,
        walletData.challenge
      );

      // Decrypt mnemonic
      const mnemonic = await decryptData(
        walletData.encryptedMnemonic,
        encryptionKey
      );

      // Derive wallet at index
      const derived = deriveWalletFromMnemonic(mnemonic, index);

      return {
        address: derived.address,
        privateKey: derived.privateKey,
      };
    } catch (error) {
      this.config.onError?.(error as any);
      throw new WalletError("Failed to derive wallet", error);
    }
  }

  /**
   * Export the mnemonic phrase
   * Requires fresh authentication
   */
  async exportMnemonic(): Promise<string> {
    try {
      if (!this.currentUser) {
        throw new WalletError("Must be authenticated to export mnemonic");
      }

      const walletData = await this.walletStorage.retrieve(
        this.currentUser.ethereumAddress
      );

      if (!walletData) {
        throw new WalletError("No wallet found");
      }

      // Re-authenticate to decrypt
      const authResult = await login();
      if (!authResult.user) {
        throw new WalletError("Re-authentication failed");
      }

      const encryptionKey = await deriveEncryptionKey(
        walletData.credentialId,
        walletData.challenge
      );

      const mnemonic = await decryptData(
        walletData.encryptedMnemonic,
        encryptionKey
      );

      return mnemonic;
    } catch (error) {
      this.config.onError?.(error as any);
      throw new WalletError("Failed to export mnemonic", error);
    }
  }

  /**
   * Import a mnemonic phrase
   * Encrypts and stores it for the current user
   * Requires fresh authentication
   * WARNING: This will overwrite any existing wallet for this user
   */
  async importMnemonic(mnemonic: string): Promise<void> {
    try {
      if (!this.currentUser) {
        throw new WalletError("Must be authenticated to import mnemonic");
      }

      // Validate the mnemonic format
      if (!mnemonic || mnemonic.trim().split(/\s+/).length < 12) {
        throw new WalletError("Invalid mnemonic: must be at least 12 words");
      }

      // Re-authenticate to get fresh credentials for encryption
      const authResult = await login();
      if (!authResult.user) {
        throw new WalletError("Re-authentication failed");
      }

      const credentialId = authResult.user.credentialId;

      // Generate a challenge for encryption key derivation
      const challenge = this.generateChallenge();

      // Derive encryption key from WebAuthn credentials
      const encryptionKey = await deriveEncryptionKey(credentialId, challenge);

      // Encrypt the mnemonic
      const encryptedMnemonic = await encryptData(
        mnemonic.trim(),
        encryptionKey
      );

      // Store encrypted wallet
      await this.walletStorage.store({
        ethereumAddress: this.currentUser.ethereumAddress,
        encryptedMnemonic,
        credentialId,
        challenge,
        createdAt: Date.now(),
      });

      this.currentWallet = {
        address: this.currentUser.ethereumAddress,
        mnemonic: mnemonic.trim(),
      };
    } catch (error) {
      this.config.onError?.(error as any);
      throw new WalletError("Failed to import mnemonic", error);
    }
  }

  /**
   * Sign a message with the wallet
   * Requires fresh authentication
   */
  async signMessage(message: string): Promise<string> {
    try {
      if (!this.currentUser) {
        throw new WalletError("Must be authenticated to sign message");
      }

      // Re-authenticate to get fresh credentials
      const authResult = await login();
      if (!authResult.user) {
        throw new WalletError("Re-authentication failed");
      }

      const challenge = this.generateChallenge();

      const signature = await this.walletSigner.signMessage(
        this.currentUser.ethereumAddress,
        message,
        authResult.user.credentialId,
        challenge
      );

      return signature;
    } catch (error) {
      this.config.onError?.(error as any);
      throw new WalletError("Failed to sign message", error);
    }
  }

  /**
   * Get RPC endpoints for a chain
   */
  async getEndpoints(chainId: number): Promise<string[]> {
    return getEndpoints(chainId);
  }

  /**
   * Check if a network supports EIP-7702
   */
  async supportsEIP7702(
    chainId: number,
    options?: { maxEndpoints?: number; timeout?: number }
  ): Promise<boolean> {
    return supportsEIP7702(chainId, this.getEndpoints.bind(this), options);
  }

  /**
   * Access ZK proof module (if available)
   */
  get zk(): any {
    if (!this.zkModule) {
      throw new Error(
        "ZK module not available. Install dependencies: npm install snarkjs circomlibjs"
      );
    }
    return this.zkModule;
  }

  /**
   * Generate a random challenge
   */
  private generateChallenge(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode(...array))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }
}
