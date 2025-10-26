/**
 * Main Web3Passkey SDK class - Client-Only Version
 * No server required - all authentication happens locally
 */

import { register } from "../auth/register";
import { login } from "../auth/authenticate";
import { IndexedDBWalletStorage } from "../wallet/storage";
import {
  generateBIP39Wallet,
  deriveWalletFromMnemonic,
} from "../wallet/generate";
import {
  deriveEncryptionKeyFromWebAuthn,
  encryptData,
  decryptData,
} from "../wallet/crypto";
import { StealthAddressModule } from "../stealth";
import { SessionManager } from "./session";
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
  private currentUser: UserInfo | null = null;
  private currentWallet: WalletInfo | null = null;
  private sessionManager: SessionManager;

  // Optional modules
  public stealth?: StealthAddressModule;
  private zkModule?: any;

  constructor(config: Web3PasskeyConfig = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config } as InternalConfig;
    this.walletStorage = new IndexedDBWalletStorage();
    this.sessionManager = new SessionManager(config.sessionDuration || 1);

    // Initialize optional modules
    if (config.stealthAddresses !== undefined) {
      this.stealth = new StealthAddressModule(
        config.stealthAddresses,
        (requireAuth?: boolean) => this.getMnemonicFromSession(requireAuth)
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
   * Get mnemonic from active session or trigger authentication
   * This is used internally by methods that need the mnemonic
   *
   * @param forceAuth - If true, bypass session cache and require fresh authentication
   */
  private async getMnemonicFromSession(
    forceAuth: boolean = false
  ): Promise<string> {
    // Check if session is active (unless force auth is required)
    if (!forceAuth) {
      const cachedMnemonic = this.sessionManager.getMnemonic();
      if (cachedMnemonic) {
        return cachedMnemonic;
      }
    }

    // Session expired, doesn't exist, or force auth requested - need to authenticate
    if (!this.currentUser) {
      throw new WalletError("Must be authenticated. Call login() first.");
    }

    // Get encrypted wallet
    const walletData = await this.walletStorage.retrieve(
      this.currentUser.ethereumAddress
    );

    if (!walletData) {
      throw new WalletError("No wallet found. Generate a wallet first.");
    }

    // Authenticate to prove identity
    const authResult = await login();
    if (!authResult.user) {
      throw new WalletError("Authentication failed");
    }

    // Get credential to access public key
    const storage = new (await import("../auth/storage")).CredentialStorage();
    const credential = storage.getCredentialById(walletData.credentialId);
    const publicKey = credential?.publicKey;

    // Derive decryption key from WebAuthn credential
    const encryptionKey = await deriveEncryptionKeyFromWebAuthn(
      walletData.credentialId,
      publicKey
    );

    // Decrypt mnemonic
    const mnemonic = await decryptData(
      walletData.encryptedMnemonic,
      encryptionKey
    );

    // Start new session with decrypted mnemonic
    this.sessionManager.startSession(mnemonic, walletData.credentialId);

    return mnemonic;
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

      const registrationResult = await register({
        username: options.username,
        ethereumAddress,
      });

      this.currentUser = {
        id: ethereumAddress,
        username: options.username,
        displayName: options.username,
        ethereumAddress,
      };

      const storage = new (await import("../auth/storage")).CredentialStorage();
      const credential = storage.getCredentialByAddress(ethereumAddress);

      if (!credential) {
        throw new WalletError("Credential not found after registration");
      }

      const credentialId = credential.id;
      const publicKey = credential.publicKey;

      // Derive encryption key from WebAuthn credential
      const encryptionKey = await deriveEncryptionKeyFromWebAuthn(
        credentialId,
        publicKey
      );

      const encryptedMnemonic = await encryptData(mnemonic, encryptionKey);

      await this.walletStorage.store({
        ethereumAddress: this.currentUser.ethereumAddress,
        encryptedMnemonic,
        credentialId,
        createdAt: Date.now(),
      });

      this.sessionManager.startSession(mnemonic, credentialId);

      this.config.onAuthStateChanged?.(true, this.currentUser);

      return { mnemonic };
    } catch (error) {
      this.config.onError?.(error as any);
      throw error;
    }
  }

  /**
   * Login with WebAuthn (usernameless)
   * Uses resident credentials stored in the authenticator
   * Automatically starts a session with the decrypted mnemonic
   */
  async login(): Promise<UserInfo> {
    try {
      const result = await login();

      if (!result.verified || !result.user) {
        throw new AuthenticationError("Login failed");
      }

      this.currentUser = {
        id: result.user.ethereumAddress,
        username: result.user.username,
        displayName: result.user.username,
        ethereumAddress: result.user.ethereumAddress,
      };

      // Get encrypted wallet data
      const walletData = await this.walletStorage.retrieve(
        this.currentUser.ethereumAddress
      );

      if (!walletData) {
        throw new WalletError(
          "No wallet found for this user. You may need to register first."
        );
      }

      // Get credential to access public key
      const storage = new (await import("../auth/storage")).CredentialStorage();
      const credential = storage.getCredentialById(walletData.credentialId);
      const publicKey = credential?.publicKey;

      // Derive decryption key from WebAuthn credential
      const encryptionKey = await deriveEncryptionKeyFromWebAuthn(
        walletData.credentialId,
        publicKey
      );

      // Decrypt mnemonic
      const mnemonic = await decryptData(
        walletData.encryptedMnemonic,
        encryptionKey
      );

      // Start session with decrypted mnemonic
      this.sessionManager.startSession(mnemonic, walletData.credentialId);

      this.config.onAuthStateChanged?.(true, this.currentUser);

      return this.currentUser;
    } catch (error) {
      this.config.onError?.(error as any);
      throw error;
    }
  }

  /**
   * Logout the current user
   * Clears the active session and removes cached mnemonic from memory
   */
  async logout(): Promise<void> {
    this.currentUser = null;
    this.currentWallet = null;
    this.sessionManager.clearSession();
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
   */
  async generateWallet(): Promise<{ mnemonic: string }> {
    try {
      const wallet = generateBIP39Wallet();

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
   * Derive an HD wallet at a specific index
   *
   * SECURITY: Uses active session or prompts for authentication if session expired
   *
   * @param index - The HD wallet derivation index
   * @param options - Optional configuration
   * @param options.requireAuth - If true, force fresh authentication even if session is active
   */
  async deriveWallet(
    index: number,
    options?: { requireAuth?: boolean }
  ): Promise<WalletInfo> {
    try {
      if (!this.currentUser) {
        throw new WalletError("Must be authenticated to derive wallet");
      }

      const mnemonic = await this.getMnemonicFromSession(options?.requireAuth);

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
   *
   * SECURITY: Uses active session or prompts for authentication if session expired
   *
   * @param options - Optional configuration
   * @param options.requireAuth - If true, force fresh authentication even if session is active
   */
  async exportMnemonic(options?: { requireAuth?: boolean }): Promise<string> {
    try {
      if (!this.currentUser) {
        throw new WalletError("Must be authenticated to export mnemonic");
      }

      return await this.getMnemonicFromSession(options?.requireAuth);
    } catch (error) {
      this.config.onError?.(error as any);
      throw new WalletError("Failed to export mnemonic", error);
    }
  }

  /**
   * Import a mnemonic phrase
   * Encrypts and stores it for the current user
   * Requires fresh WebAuthn authentication for security
   * WARNING: This will overwrite any existing wallet for this user
   */
  async importMnemonic(mnemonic: string): Promise<void> {
    try {
      if (!this.currentUser) {
        throw new WalletError("Must be authenticated to import mnemonic");
      }

      if (!mnemonic || mnemonic.trim().split(/\s+/).length < 12) {
        throw new WalletError("Invalid mnemonic: must be at least 12 words");
      }

      const authResult = await login();
      if (!authResult.user) {
        throw new WalletError("Authentication failed");
      }

      const credentialId = authResult.user.credentialId;

      // Get credential to access public key
      const storage = new (await import("../auth/storage")).CredentialStorage();
      const credential = storage.getCredentialById(credentialId);
      const publicKey = credential?.publicKey;

      // Derive encryption key from WebAuthn credential
      const encryptionKey = await deriveEncryptionKeyFromWebAuthn(
        credentialId,
        publicKey
      );

      const encryptedMnemonic = await encryptData(
        mnemonic.trim(),
        encryptionKey
      );

      await this.walletStorage.store({
        ethereumAddress: this.currentUser.ethereumAddress,
        encryptedMnemonic,
        credentialId,
        createdAt: Date.now(),
      });

      this.currentWallet = {
        address: this.currentUser.ethereumAddress,
        mnemonic: mnemonic.trim(),
      };

      this.sessionManager.startSession(mnemonic.trim(), credentialId);
    } catch (error) {
      this.config.onError?.(error as any);
      throw new WalletError("Failed to import mnemonic", error);
    }
  }

  /**
   * Sign a message with the wallet
   *
   * SECURITY: Uses active session or prompts for authentication if session expired
   *
   * @param message - The message to sign
   * @param options - Optional configuration
   * @param options.requireAuth - If true, force fresh authentication even if session is active
   */
  async signMessage(
    message: string,
    options?: { requireAuth?: boolean }
  ): Promise<string> {
    try {
      if (!this.currentUser) {
        throw new WalletError("Must be authenticated to sign message");
      }

      const mnemonic = await this.getMnemonicFromSession(options?.requireAuth);

      const { Wallet } = await import("ethers");
      const wallet = Wallet.fromPhrase(mnemonic);

      const signature = await wallet.signMessage(message);

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

  // ========================================
  // Session Management
  // ========================================

  /**
   * Check if there's an active session
   */
  hasActiveSession(): boolean {
    return this.sessionManager.isActive();
  }

  /**
   * Get remaining session time in seconds
   */
  getSessionRemainingTime(): number {
    return this.sessionManager.getRemainingTime();
  }

  /**
   * Extend the current session by the configured duration
   * Throws error if no active session or if session expired
   */
  extendSession(): void {
    try {
      this.sessionManager.extendSession();
    } catch (error) {
      throw new WalletError("Cannot extend session", error);
    }
  }

  /**
   * Manually clear the active session
   * This removes the cached mnemonic from memory
   * User will need to authenticate again for wallet operations
   */
  clearSession(): void {
    this.sessionManager.clearSession();
  }

  /**
   * Update session duration (affects new sessions and extensions)
   * @param hours - Session duration in hours
   */
  setSessionDuration(hours: number): void {
    this.sessionManager.setSessionDuration(hours);
  }

  /**
   * SDK version
   */
  get version(): string {
    return "0.7.0";
  }
}
