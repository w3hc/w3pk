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

    // ZK module will be lazy-loaded on first access (no eager initialization)
  }

  /**
   * Lazy-load ZK module only when accessed
   * This prevents bundlers from including circomlibjs unless ZK features are used
   */
  private async loadZKModule() {
    if (this.zkModule) {
      return this.zkModule;
    }

    try {
      // Use Function constructor to completely hide import from webpack
      const dynamicImport = new Function("path", "return import(path)");
      const { ZKProofModule } = await dynamicImport("w3pk/zk");
      const zkConfig = (this.config as any).zkProofs || {};
      this.zkModule = new ZKProofModule(zkConfig);
      return this.zkModule;
    } catch (error) {
      throw new Error(
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
    const credential = await storage.getCredentialById(walletData.credentialId);
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
   * Returns the derived address #0 and username
   */
  async register(options: {
    username: string;
  }): Promise<{ address: string; username: string }> {
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

      this.currentUser = {
        id: ethereumAddress,
        username: options.username,
        displayName: options.username,
        ethereumAddress,
      };

      const storage = new (await import("../auth/storage")).CredentialStorage();
      const credential = await storage.getCredentialByAddress(ethereumAddress);

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
        createdAt: new Date().toISOString(),
      });

      this.sessionManager.startSession(mnemonic, credentialId);

      // Set currentWallet to ensure wallet state is available
      this.currentWallet = {
        address: ethereumAddress,
        mnemonic,
      };

      this.config.onAuthStateChanged?.(true, this.currentUser);

      return { address: ethereumAddress, username: options.username };
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
      const credential = await storage.getCredentialById(walletData.credentialId);
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
      const credential = await storage.getCredentialById(credentialId);
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
        createdAt: new Date().toISOString(),
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
   * Sign an EIP-7702 authorization for gasless transactions
   *
   * This allows your EOA to temporarily delegate code execution to a contract,
   * enabling the contract to sponsor gas costs for your transactions.
   *
   * SECURITY: Uses active session or prompts for authentication if session expired
   *
   * @param params - Authorization parameters
   * @param params.contractAddress - The contract address to authorize
   * @param params.chainId - Optional chain ID (defaults to 1 for mainnet)
   * @param params.nonce - Optional nonce (defaults to 0)
   * @param params.privateKey - Optional private key to sign with (for derived or stealth addresses)
   * @param options - Optional configuration
   * @param options.requireAuth - If true, force fresh authentication even if session is active
   *
   * @returns EIP-7702 authorization object with signature components
   *
   * @example
   * ```typescript
   * // Sign authorization with default address (index 0)
   * const authorization = await sdk.signAuthorization({
   *   contractAddress: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1',
   *   chainId: 11155111, // Sepolia
   * });
   *
   * // Sign from a derived address
   * const { privateKey } = deriveWalletFromMnemonic(mnemonic, 5);
   * const authFromDerived = await sdk.signAuthorization({
   *   contractAddress: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1',
   *   chainId: 11155111,
   *   privateKey, // Use private key from derived index
   * });
   *
   * // Sign from a stealth address
   * const stealthPrivKey = computeStealthPrivateKey(viewingKey, spendingKey, ephemeralPubKey);
   * const authFromStealth = await sdk.signAuthorization({
   *   contractAddress: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1',
   *   chainId: 11155111,
   *   privateKey: stealthPrivKey, // Use computed stealth private key
   * });
   *
   * // Use with viem or ethers to submit gasless transaction
   * await walletClient.sendTransaction({
   *   to: govContractAddress,
   *   data: encodeFunctionData({
   *     abi: govAbi,
   *     functionName: 'propose',
   *     args: [targets, values, calldatas, description]
   *   }),
   *   authorizationList: [authorization]
   * });
   * ```
   */
  async signAuthorization(
    params: {
      contractAddress: string;
      chainId?: number;
      nonce?: bigint;
      privateKey?: string;
    },
    options?: { requireAuth?: boolean }
  ): Promise<{
    chainId: bigint;
    address: string;
    nonce: bigint;
    yParity: number;
    r: string;
    s: string;
  }> {
    try {
      if (!this.currentUser) {
        throw new WalletError("Must be authenticated to sign authorization");
      }

      const { Wallet, keccak256, concat, toBeHex, Signature } = await import("ethers");

      let wallet: any;
      let signerAddress: string;

      // If privateKey is provided, use it directly (for derived or stealth addresses)
      if (params.privateKey) {
        wallet = new Wallet(params.privateKey);
        signerAddress = wallet.address;
      } else {
        // Use default wallet (index 0) from mnemonic
        const mnemonic = await this.getMnemonicFromSession(options?.requireAuth);
        wallet = Wallet.fromPhrase(mnemonic);
        signerAddress = wallet.address;
      }

      // Get chain ID (default to 1 for mainnet)
      const chainId = BigInt(params.chainId || 1);

      // Get nonce (default to 0)
      const nonce = params.nonce || 0n;

      // Construct EIP-7702 authorization message
      // Format: 0x05 || rlp([chain_id, address, nonce])
      const authorizationMessage = concat([
        "0x05", // EIP-7702 magic byte
        toBeHex(chainId, 32),
        params.contractAddress.toLowerCase(),
        toBeHex(nonce, 32)
      ]);

      // Hash the authorization message
      const messageHash = keccak256(authorizationMessage);

      // Sign the message hash
      const signature = wallet.signingKey.sign(messageHash);

      // Parse signature into components
      const sig = Signature.from(signature);

      // Return EIP-7702 authorization object
      return {
        chainId,
        address: signerAddress.toLowerCase(),
        nonce,
        yParity: sig.yParity,
        r: sig.r,
        s: sig.s
      };
    } catch (error) {
      this.config.onError?.(error as any);
      throw new WalletError("Failed to sign authorization", error);
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
    // Return a proxy that loads ZK module on first method call
    return new Proxy(
      {},
      {
        get: (_target, prop) => {
          return async (...args: any[]) => {
            const zkModule = await this.loadZKModule();
            return zkModule[prop](...args);
          };
        },
      }
    );
  }

  // ========================================
  // Backup and Recovery
  // ========================================

  /**
   * Get comprehensive backup status
   * Shows user exactly what protects their wallet
   */
  async getBackupStatus(): Promise<any> {
    if (!this.currentUser) {
      throw new WalletError("Must be authenticated to check backup status");
    }

    const { BackupManager } = await import("../backup");
    const backupManager = new BackupManager();
    return backupManager.getBackupStatus(this.currentUser.ethereumAddress);
  }

  /**
   * Create password-protected ZIP backup
   * @param password - Strong password to encrypt the backup
   * @param options - Optional backup configuration
   */
  async createZipBackup(
    password: string,
    options?: { includeInstructions?: boolean; deviceBinding?: boolean }
  ): Promise<Blob> {
    if (!this.currentUser) {
      throw new WalletError("Must be authenticated to create backup");
    }

    const mnemonic = await this.getMnemonicFromSession(true); // Force auth for security

    const { BackupManager } = await import("../backup");
    const backupManager = new BackupManager();

    return backupManager.createZipBackup(
      mnemonic,
      this.currentUser.ethereumAddress,
      { password, ...options }
    );
  }

  /**
   * Create QR code backup
   * @param password - Optional password to encrypt QR code
   * @param options - QR code configuration
   */
  async createQRBackup(
    password?: string,
    options?: { errorCorrection?: "L" | "M" | "Q" | "H" }
  ): Promise<{ qrCodeDataURL: string; instructions: string }> {
    if (!this.currentUser) {
      throw new WalletError("Must be authenticated to create backup");
    }

    const mnemonic = await this.getMnemonicFromSession(true); // Force auth for security

    const { BackupManager } = await import("../backup");
    const backupManager = new BackupManager();

    return backupManager.createQRBackup(
      mnemonic,
      this.currentUser.ethereumAddress,
      { password, ...options }
    );
  }

  /**
   * Set up social recovery
   * Splits mnemonic into M-of-N shares for guardian-based recovery
   *
   * @param guardians - Array of guardian information
   * @param threshold - Number of guardians required to recover (M in M-of-N)
   */
  async setupSocialRecovery(
    guardians: { name: string; email?: string; phone?: string }[],
    threshold: number
  ): Promise<any[]> {
    if (!this.currentUser) {
      throw new WalletError("Must be authenticated to set up social recovery");
    }

    const mnemonic = await this.getMnemonicFromSession(true); // Force auth for security

    const { SocialRecoveryManager } = await import("../recovery");
    const socialRecovery = new SocialRecoveryManager();

    return socialRecovery.setupSocialRecovery(
      mnemonic,
      this.currentUser.ethereumAddress,
      guardians,
      threshold
    );
  }

  /**
   * Generate guardian invitation
   * Creates QR code and instructions for a guardian
   */
  async generateGuardianInvite(guardianId: string): Promise<any> {
    const { SocialRecoveryManager } = await import("../recovery");
    const socialRecovery = new SocialRecoveryManager();

    const config = socialRecovery.getSocialRecoveryConfig();
    if (!config) {
      throw new WalletError("Social recovery not configured");
    }

    const guardian = config.guardians.find((g) => g.id === guardianId);
    if (!guardian) {
      throw new WalletError("Guardian not found");
    }

    return socialRecovery.generateGuardianInvite(guardian);
  }

  /**
   * Recover wallet from guardian shares
   * @param shares - Array of share data from guardians (JSON strings)
   */
  async recoverFromGuardians(
    shares: string[]
  ): Promise<{ mnemonic: string; ethereumAddress: string }> {
    const { SocialRecoveryManager } = await import("../recovery");
    const socialRecovery = new SocialRecoveryManager();

    return socialRecovery.recoverFromGuardians(shares);
  }

  /**
   * Restore wallet from encrypted backup
   * @param backupData - Backup file contents (JSON string)
   * @param password - Password used to encrypt the backup
   */
  async restoreFromBackup(
    backupData: string,
    password: string
  ): Promise<{ mnemonic: string; ethereumAddress: string }> {
    const { BackupManager } = await import("../backup");
    const backupManager = new BackupManager();

    return backupManager.restoreFromZipBackup(backupData, password);
  }

  /**
   * Restore wallet from QR code
   * @param qrData - Scanned QR code data (JSON string)
   * @param password - Optional password if QR was encrypted
   */
  async restoreFromQR(
    qrData: string,
    password?: string
  ): Promise<{ mnemonic: string; ethereumAddress: string }> {
    const { BackupManager } = await import("../backup");
    const backupManager = new BackupManager();

    return backupManager.restoreFromQR(qrData, password);
  }

  /**
   * Get cross-device sync status
   * Shows which devices have access and sync capabilities
   */
  async getSyncStatus(): Promise<any> {
    const { DeviceManager } = await import("../sync");
    const deviceManager = new DeviceManager();

    return deviceManager.getSyncStatus();
  }

  /**
   * Detect sync capabilities
   * Shows what platform sync is available (iCloud, Google, etc.)
   */
  async detectSyncCapabilities(): Promise<any> {
    const { PlatformDetector } = await import("../sync");
    const detector = new PlatformDetector();

    return detector.detectSyncCapabilities();
  }

  /**
   * Simulate recovery scenario (educational)
   * Tests what happens in various loss scenarios
   *
   * @param scenario - Type of scenario to simulate
   */
  async simulateRecoveryScenario(scenario: {
    type: "lost-device" | "lost-phrase" | "lost-both" | "switch-platform";
    description: string;
  }): Promise<any> {
    if (!this.currentUser) {
      throw new WalletError("Must be authenticated to run recovery simulation");
    }

    const status = await this.getBackupStatus();

    const { RecoverySimulator } = await import("../education");
    const simulator = new RecoverySimulator();

    return simulator.simulateScenario(scenario, status);
  }

  /**
   * Run interactive recovery test
   * Tests all recovery scenarios and provides feedback
   */
  async runRecoveryTest(): Promise<{
    scenarios: any[];
    overallScore: number;
    feedback: string;
  }> {
    if (!this.currentUser) {
      throw new WalletError("Must be authenticated to run recovery test");
    }

    const status = await this.getBackupStatus();

    const { RecoverySimulator } = await import("../education");
    const simulator = new RecoverySimulator();

    return simulator.runInteractiveTest(status);
  }

  /**
   * Get educational content
   * @param topic - Topic to explain (e.g., 'whatIsPasskey', 'socialRecoveryExplained')
   */
  async getEducation(topic: string): Promise<any> {
    const { getExplainer } = await import("../education");
    const explainer = getExplainer(topic);

    if (!explainer) {
      throw new WalletError(`Unknown education topic: ${topic}`);
    }

    return explainer;
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
}
