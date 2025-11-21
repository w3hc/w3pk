/**
 * Main Web3Passkey SDK
 *
 * SECURITY MODEL:
 * - Master mnemonic never exposed to applications
 * - Applications access only origin-specific derived wallets
 * - MAIN tag wallets expose address only (no private key)
 * - Custom tag wallets (e.g., 'GAMING', 'TRADING') include private keys
 * - Each origin receives isolated address derivation
 *
 * STEALTH ADDRESSES (opt-in via config.stealthAddresses):
 * - Applications receive stealth private keys (viewing and spending)
 * - Required for ERC-5564 compliance
 * - Uses separate derivation: m/44'/60'/1'/0/0 and m/44'/60'/1'/0/1
 * - Not derived from origin-specific addresses
 */

import { register } from "../auth/register";
import { login } from "../auth/authenticate";
import { IndexedDBWalletStorage } from "../wallet/storage";
import {
  generateBIP39Wallet,
} from "../wallet/generate";
import {
  getOriginSpecificAddress,
  getCurrentOrigin,
  DEFAULT_TAG,
} from "../wallet/origin-derivation";
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

  public stealth?: StealthAddressModule;
  private zkModule?: any;

  constructor(config: Web3PasskeyConfig = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config } as InternalConfig;
    this.walletStorage = new IndexedDBWalletStorage();
    this.sessionManager = new SessionManager(config.sessionDuration || 1);

    if (config.stealthAddresses !== undefined) {
      this.stealth = new StealthAddressModule(
        config.stealthAddresses,
        (requireAuth?: boolean) => this.getMnemonicFromSession(requireAuth)
      );
    }
  }

  /**
   * Lazy-load ZK module to prevent bundling unless accessed
   */
  private async loadZKModule() {
    if (this.zkModule) {
      return this.zkModule;
    }

    try {
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
   * Retrieve mnemonic from active session or trigger authentication
   * @param forceAuth - Bypass session cache and require fresh authentication
   */
  private async getMnemonicFromSession(
    forceAuth: boolean = false
  ): Promise<string> {
    if (!forceAuth) {
      const cachedMnemonic = this.sessionManager.getMnemonic();
      if (cachedMnemonic) {
        return cachedMnemonic;
      }
    }

    if (!this.currentUser) {
      throw new WalletError("Must be authenticated. Call login() first.");
    }

    const walletData = await this.walletStorage.retrieve(
      this.currentUser.ethereumAddress
    );

    if (!walletData) {
      throw new WalletError("No wallet found. Generate a wallet first.");
    }

    const authResult = await login();
    if (!authResult.user) {
      throw new WalletError("Authentication failed");
    }

    const storage = new (await import("../auth/storage")).CredentialStorage();
    const credential = await storage.getCredentialById(walletData.credentialId);
    const publicKey = credential?.publicKey;

    const encryptionKey = await deriveEncryptionKeyFromWebAuthn(
      walletData.credentialId,
      publicKey
    );

    const mnemonic = await decryptData(
      walletData.encryptedMnemonic,
      encryptionKey
    );

    this.sessionManager.startSession(mnemonic, walletData.credentialId);

    return mnemonic;
  }

  /**
   * Register new user with WebAuthn
   * Automatically generates wallet if none exists and associates with passkey
   */
  async register(options: {
    username: string;
  }): Promise<{ address: string; username: string }> {
    try {
      if (!this.currentWallet?.address) {
        await this.generateWallet();
      }

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
   * Login with WebAuthn using resident credentials
   * Starts session with decrypted mnemonic
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

      const walletData = await this.walletStorage.retrieve(
        this.currentUser.ethereumAddress
      );

      if (!walletData) {
        throw new WalletError(
          "No wallet found for this user. You may need to register first."
        );
      }

      const storage = new (await import("../auth/storage")).CredentialStorage();
      const credential = await storage.getCredentialById(walletData.credentialId);
      const publicKey = credential?.publicKey;

      const encryptionKey = await deriveEncryptionKeyFromWebAuthn(
        walletData.credentialId,
        publicKey
      );

      const mnemonic = await decryptData(
        walletData.encryptedMnemonic,
        encryptionKey
      );

      this.sessionManager.startSession(mnemonic, walletData.credentialId);

      this.config.onAuthStateChanged?.(true, this.currentUser);

      return this.currentUser;
    } catch (error) {
      this.config.onError?.(error as any);
      throw error;
    }
  }

  /**
   * Logout current user and clear session
   */
  async logout(): Promise<void> {
    this.currentUser = null;
    this.currentWallet = null;
    this.sessionManager.clearSession();
    this.config.onAuthStateChanged?.(false, undefined);
  }

  get isAuthenticated(): boolean {
    return this.currentUser !== null;
  }

  get user(): UserInfo | null {
    return this.currentUser;
  }

  /**
   * Check if there are existing credentials on this device
   * Useful for preventing accidental multiple wallet creation
   *
   * @returns true if at least one credential exists
   * @example
   * const hasWallet = await w3pk.hasExistingCredential()
   * if (hasWallet) {
   *   // Prompt user to login instead of registering
   *   await w3pk.login()
   * }
   */
  async hasExistingCredential(): Promise<boolean> {
    try {
      const storage = new (await import("../auth/storage")).CredentialStorage();
      const credentials = await storage.getAllCredentials();
      return credentials.length > 0;
    } catch (error) {
      // If storage fails, assume no credentials
      return false;
    }
  }

  /**
   * Get the number of existing credentials on this device
   *
   * @returns count of credentials
   * @example
   * const count = await w3pk.getExistingCredentialCount()
   * if (count > 0) {
   *   console.warn(`You have ${count} wallet(s) on this device`)
   * }
   */
  async getExistingCredentialCount(): Promise<number> {
    try {
      const storage = new (await import("../auth/storage")).CredentialStorage();
      const credentials = await storage.getAllCredentials();
      return credentials.length;
    } catch (error) {
      return 0;
    }
  }

  /**
   * List existing credentials (usernames and addresses)
   * Useful for allowing users to select which wallet to login to
   *
   * @returns array of credentials with username, address, and metadata
   * @example
   * const wallets = await w3pk.listExistingCredentials()
   * wallets.forEach(w => {
   *   console.log(`${w.username}: ${w.ethereumAddress}`)
   * })
   */
  async listExistingCredentials(): Promise<Array<{
    username: string;
    ethereumAddress: string;
    createdAt: string;
    lastUsed: string;
  }>> {
    try {
      const storage = new (await import("../auth/storage")).CredentialStorage();
      const credentials = await storage.getAllCredentials();
      return credentials.map(cred => ({
        username: cred.username,
        ethereumAddress: cred.ethereumAddress,
        createdAt: cred.createdAt,
        lastUsed: cred.lastUsed,
      }));
    } catch (error) {
      return [];
    }
  }

  /**
   * Generate new BIP39 wallet with 12-word mnemonic
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
   * Derive origin-specific wallet
   *
   * SECURITY:
   * - MAIN tag: Returns address only (no private key)
   * - Custom tags (e.g., 'GAMING', 'TRADING'): Include private key
   * - Uses active session or prompts for authentication
   *
   * @param tag - Tag for derivation (default: "MAIN")
   * @param options.requireAuth - Force fresh authentication
   * @param options.origin - Override origin URL (testing only)
   */
  async deriveWallet(
    tag?: string,
    options?: { requireAuth?: boolean; origin?: string }
  ): Promise<WalletInfo & { index?: number; origin?: string; tag?: string }> {
    try {
      if (!this.currentUser) {
        throw new WalletError("Must be authenticated to derive wallet");
      }

      const mnemonic = await this.getMnemonicFromSession(options?.requireAuth);

      const effectiveTag = tag || DEFAULT_TAG;
      const origin = options?.origin || getCurrentOrigin();

      const derived = await getOriginSpecificAddress(mnemonic, origin, effectiveTag);

      return {
        address: derived.address,
        privateKey: derived.privateKey,
        index: derived.index,
        origin: derived.origin,
        tag: derived.tag,
      };
    } catch (error) {
      this.config.onError?.(error as any);
      throw new WalletError("Failed to derive wallet", error);
    }
  }

  /**
   * Export mnemonic (disabled for security)
   * Use createZipBackup() or createQRBackup() instead
   * @deprecated
   * @throws WalletError
   */
  async exportMnemonic(): Promise<string> {
    throw new WalletError(
      "exportMnemonic() disabled for security. Use createZipBackup() or createQRBackup() instead."
    );
  }

  /**
   * Import mnemonic phrase
   * Requires authentication and overwrites existing wallet
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

      const storage = new (await import("../auth/storage")).CredentialStorage();
      const credential = await storage.getCredentialById(credentialId);
      const publicKey = credential?.publicKey;

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
   * Sign message with wallet
   * @param options.requireAuth - Force fresh authentication
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
   * Sign EIP-7702 authorization for gasless transactions
   * Allows EOA to delegate execution to contract for gas sponsorship
   *
   * @param params.contractAddress - Contract address to authorize
   * @param params.chainId - Chain ID (default: 1)
   * @param params.nonce - Nonce (default: 0)
   * @param params.privateKey - Private key for derived/stealth addresses
   * @param options.requireAuth - Force fresh authentication
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

      if (params.privateKey) {
        wallet = new Wallet(params.privateKey);
        signerAddress = wallet.address;
      } else {
        const mnemonic = await this.getMnemonicFromSession(options?.requireAuth);
        wallet = Wallet.fromPhrase(mnemonic);
        signerAddress = wallet.address;
      }

      const chainId = BigInt(params.chainId || 1);
      const nonce = params.nonce || 0n;

      const authorizationMessage = concat([
        "0x05",
        toBeHex(chainId, 32),
        params.contractAddress.toLowerCase(),
        toBeHex(nonce, 32)
      ]);

      const messageHash = keccak256(authorizationMessage);
      const signature = wallet.signingKey.sign(messageHash);
      const sig = Signature.from(signature);

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

  async getEndpoints(chainId: number): Promise<string[]> {
    return getEndpoints(chainId);
  }

  async supportsEIP7702(
    chainId: number,
    options?: { maxEndpoints?: number; timeout?: number }
  ): Promise<boolean> {
    return supportsEIP7702(chainId, this.getEndpoints.bind(this), options);
  }

  get zk(): any {
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

  /**
   * Get backup status
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
   */
  async createZipBackup(
    password: string,
    options?: { includeInstructions?: boolean; deviceBinding?: boolean }
  ): Promise<Blob> {
    if (!this.currentUser) {
      throw new WalletError("Must be authenticated to create backup");
    }

    const mnemonic = await this.getMnemonicFromSession(true);

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
   */
  async createQRBackup(
    password?: string,
    options?: { errorCorrection?: "L" | "M" | "Q" | "H" }
  ): Promise<{ qrCodeDataURL: string; instructions: string }> {
    if (!this.currentUser) {
      throw new WalletError("Must be authenticated to create backup");
    }

    const mnemonic = await this.getMnemonicFromSession(true);

    const { BackupManager } = await import("../backup");
    const backupManager = new BackupManager();

    return backupManager.createQRBackup(
      mnemonic,
      this.currentUser.ethereumAddress,
      { password, ...options }
    );
  }

  /**
   * Set up social recovery with M-of-N guardian shares
   * @param threshold - Number of guardians required to recover
   */
  async setupSocialRecovery(
    guardians: { name: string; email?: string; phone?: string }[],
    threshold: number
  ): Promise<any[]> {
    if (!this.currentUser) {
      throw new WalletError("Must be authenticated to set up social recovery");
    }

    const mnemonic = await this.getMnemonicFromSession(true);

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
   * Generate guardian invitation with QR code
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
   */
  async getSyncStatus(): Promise<any> {
    const { DeviceManager } = await import("../sync");
    const deviceManager = new DeviceManager();

    return deviceManager.getSyncStatus();
  }

  /**
   * Detect platform sync capabilities
   */
  async detectSyncCapabilities(): Promise<any> {
    const { PlatformDetector } = await import("../sync");
    const detector = new PlatformDetector();

    return detector.detectSyncCapabilities();
  }

  /**
   * Simulate recovery scenario
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
   * Get educational content by topic
   */
  async getEducation(topic: string): Promise<any> {
    const { getExplainer } = await import("../education");
    const explainer = getExplainer(topic);

    if (!explainer) {
      throw new WalletError(`Unknown education topic: ${topic}`);
    }

    return explainer;
  }

  hasActiveSession(): boolean {
    return this.sessionManager.isActive();
  }

  getSessionRemainingTime(): number {
    return this.sessionManager.getRemainingTime();
  }

  /**
   * Extend current session
   */
  extendSession(): void {
    try {
      this.sessionManager.extendSession();
    } catch (error) {
      throw new WalletError("Cannot extend session", error);
    }
  }

  /**
   * Clear active session
   */
  clearSession(): void {
    this.sessionManager.clearSession();
  }

  /**
   * Update session duration
   * @param hours - Duration in hours
   */
  setSessionDuration(hours: number): void {
    this.sessionManager.setSessionDuration(hours);
  }
}
