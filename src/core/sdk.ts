/**
 * Main Web3Passkey SDK class
 */

import {
  startRegistration,
  startAuthentication,
} from "@simplewebauthn/browser";
import { ApiClient } from "../utils/api";
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
import type {
  Web3PasskeyConfig,
  InternalConfig,
  StealthAddressConfig,
  ZKProofConfig,
} from "./config";
import { DEFAULT_CONFIG } from "./config";
import type { UserInfo, WalletInfo } from "../types";

export interface AuthResult {
  verified: boolean;
  user?: UserInfo;
}

export class Web3Passkey {
  private config: InternalConfig;
  private apiClient: ApiClient;
  private storage: IndexedDBWalletStorage;
  private signer: WalletSigner;
  private stealthModule?: StealthAddressModule;
  private zkModule?: any; // Dynamically imported to avoid bundling ZK dependencies
  private currentUser: UserInfo | null = null;
  private currentMnemonic: string | null = null;

  constructor(config: Web3PasskeyConfig) {
    // Merge with defaults
    this.config = {
      ...DEFAULT_CONFIG,
      ...config,
      timeout: config.timeout ?? DEFAULT_CONFIG.timeout!,
      debug: config.debug ?? DEFAULT_CONFIG.debug!,
    } as InternalConfig;

    // Initialize API client
    this.apiClient = new ApiClient(this.config.apiBaseUrl, this.config.timeout);

    // Initialize storage
    this.storage = new IndexedDBWalletStorage();
    this.storage.init().catch((error) => {
      if (this.config.onError) {
        this.config.onError(error);
      }
    });

    // Initialize signer
    this.signer = new WalletSigner(this.storage);

    // Initialize stealth address module if configured
    if (this.config.stealthAddresses) {
      this.stealthModule = new StealthAddressModule(
        this.config.stealthAddresses,
        this.getMnemonic.bind(this)
      );
    }

    // ZK module initialization handled separately through enableZKProofs()
    // to avoid bundling ZK dependencies in the main package

    this.log("SDK initialized");
  }

  // ========================================
  // Authentication Methods
  // ========================================

  /**
   * Register a new user with WebAuthn
   * Automatically generates and encrypts a BIP39 wallet
   */
  async register(options: {
    username: string;
    ethereumAddress: string;
  }): Promise<void> {
    try {
      const { username } = options;

      this.log(`Registering user: ${username}`);

      // Step 1: Generate BIP39 wallet
      const wallet = generateBIP39Wallet();
      this.log(`Generated wallet: ${wallet.address}`);

      // Step 2: Begin WebAuthn registration
      const beginResponse = await this.apiClient.post(
        "/webauthn/register/begin",
        {
          username,
          ethereumAddress: wallet.address,
        }
      );

      if (!beginResponse.success || !beginResponse.data?.options) {
        throw new Error("Failed to get registration options from server");
      }

      // Step 3: WebAuthn registration
      const credential = await startRegistration(beginResponse.data.options);

      // Step 4: Complete registration
      const completeResponse = await this.apiClient.post(
        "/webauthn/register/complete",
        {
          ethereumAddress: wallet.address,
          response: credential,
        }
      );

      if (!completeResponse.success) {
        throw new Error("Registration verification failed");
      }

      // Step 5: Encrypt and store wallet
      const credentialId = credential.id;
      const challenge = beginResponse.data.options.challenge;

      const encryptionKey = await deriveEncryptionKey(credentialId, challenge);
      const encryptedMnemonic = await encryptData(
        wallet.mnemonic,
        encryptionKey
      );

      await this.storage.store({
        ethereumAddress: wallet.address,
        encryptedMnemonic,
        credentialId,
        challenge,
        createdAt: Date.now(),
      });

      this.log("Registration successful");

      // Set current user
      this.currentUser = {
        id: credential.id,
        username,
        displayName: username,
        ethereumAddress: wallet.address,
      };

      this.currentMnemonic = wallet.mnemonic;

      if (this.config.onAuthStateChanged) {
        this.config.onAuthStateChanged(true, this.currentUser ?? undefined);
      }
    } catch (error) {
      this.log(`Registration failed: ${error}`, "error");
      if (this.config.onError) {
        this.config.onError(error as any);
      }
      throw error;
    }
  }

  /**
   * Authenticate with WebAuthn (usernameless flow)
   * Decrypts the wallet after successful authentication
   */
  async login(): Promise<AuthResult> {
    try {
      this.log("Starting login");

      // Step 1: Begin usernameless authentication
      const beginResponse = await this.apiClient.post(
        "/webauthn/authenticate/usernameless/begin",
        {}
      );

      if (!beginResponse.success || !beginResponse.data) {
        throw new Error(
          "Failed to get usernameless authentication options from server"
        );
      }

      const webauthnOptions = beginResponse.data.options || beginResponse.data;

      // Step 2: WebAuthn authentication
      const credential = await startAuthentication(webauthnOptions);

      // Step 3: Complete authentication
      const completeResponse = await this.apiClient.post(
        "/webauthn/authenticate/usernameless/complete",
        {
          response: credential,
        }
      );

      if (!completeResponse.success) {
        throw new Error("Usernameless authentication verification failed");
      }

      const user = completeResponse.data?.user;

      if (!user) {
        throw new Error("No user data returned from authentication");
      }

      this.log(`Authenticated user: ${user.username}`);

      // Step 4: Decrypt wallet
      const walletData = await this.storage.retrieve(user.ethereumAddress);

      if (walletData) {
        const encryptionKey = await deriveEncryptionKey(
          walletData.credentialId,
          walletData.challenge
        );

        this.currentMnemonic = await decryptData(
          walletData.encryptedMnemonic,
          encryptionKey
        );

        this.log("Wallet decrypted successfully");
      }

      // Set current user
      this.currentUser = user;

      if (this.config.onAuthStateChanged) {
        this.config.onAuthStateChanged(true, this.currentUser ?? undefined);
      }

      return {
        verified: true,
        user,
      };
    } catch (error) {
      this.log(`Login failed: ${error}`, "error");
      if (this.config.onError) {
        this.config.onError(error as any);
      }
      throw error;
    }
  }

  /**
   * Logout - clears current session
   */
  async logout(): Promise<void> {
    this.currentUser = null;
    this.currentMnemonic = null;

    if (this.config.onAuthStateChanged) {
      this.config.onAuthStateChanged(false, undefined);
    }

    this.log("Logged out");
  }

  // ========================================
  // Wallet Methods
  // ========================================

  /**
   * Generate a new BIP39 wallet
   * Note: This is a utility method and doesn't require authentication
   */
  async generateWallet(): Promise<WalletInfo> {
    const wallet = generateBIP39Wallet();
    return {
      address: wallet.address,
      mnemonic: wallet.mnemonic,
    };
  }

  /**
   * Get the current user's wallet address
   */
  get walletAddress(): string | null {
    return this.currentUser?.ethereumAddress || null;
  }

  /**
   * Get the current user's mnemonic (only after authentication)
   */
  private async getMnemonic(): Promise<string | null> {
    return this.currentMnemonic;
  }

  /**
   * Export wallet mnemonic (requires authentication)
   */
  async exportMnemonic(): Promise<string> {
    if (!this.currentMnemonic) {
      throw new Error("Not authenticated. Please login first.");
    }
    return this.currentMnemonic;
  }

  /**
   * Derive HD wallet at specific index
   */
  async deriveWallet(index: number = 0): Promise<{
    address: string;
    privateKey: string;
  }> {
    if (!this.currentMnemonic) {
      throw new Error("Not authenticated. Please login first.");
    }

    return deriveWalletFromMnemonic(this.currentMnemonic, index);
  }

  /**
   * Sign a message with the encrypted wallet
   */
  async signMessage(message: string): Promise<string> {
    if (!this.currentUser) {
      throw new Error("Not authenticated. Please login first.");
    }

    const walletData = await this.storage.retrieve(
      this.currentUser.ethereumAddress
    );

    if (!walletData) {
      throw new Error("No wallet found for current user");
    }

    return this.signer.signMessage(
      this.currentUser.ethereumAddress,
      message,
      walletData.credentialId,
      walletData.challenge
    );
  }

  // ========================================
  // Stealth Address Methods
  // ========================================

  /**
   * Access stealth address capabilities
   * Returns undefined if stealth addresses not configured
   */
  get stealth(): StealthAddressModule | undefined {
    return this.stealthModule;
  }

  /**
   * Check if stealth addresses are available
   */
  get hasStealthAddresses(): boolean {
    return this.stealthModule !== undefined;
  }

  /**
   * Enable stealth addresses after initialization
   */
  enableStealthAddresses(config: StealthAddressConfig = {}): void {
    if (!this.stealthModule) {
      this.stealthModule = new StealthAddressModule(
        config,
        this.getMnemonic.bind(this)
      );
    }
  }

  // ========================================
  // ZK Proof Methods
  // ========================================

  /**
   * Access ZK proof capabilities
   * Returns undefined if ZK proofs not configured
   */
  get zk(): any | undefined {
    return this.zkModule;
  }

  /**
   * Check if ZK proofs are available
   */
  get hasZKProofs(): boolean {
    return this.zkModule !== undefined;
  }

  /**
   * Enable ZK proofs after initialization
   * Note: ZK functionality moved to separate entry point (w3pk/zk)
   * to avoid bundling heavy dependencies in main package
   */
  async enableZKProofs(_config: ZKProofConfig = {}): Promise<void> {
    throw new Error(
      "ZK functionality has been moved to separate entry point.\n\n" +
        "Use instead:\n" +
        "  import { ZKProofModule } from 'w3pk/zk'\n\n" +
        "This prevents heavy ZK dependencies from being bundled\n" +
        "unless explicitly imported by developers who need them.\n\n" +
        "See: https://github.com/w3hc/w3pk#zero-knowledge-proofs"
    );
  }

  // ========================================
  // State & Info Methods
  // ========================================

  /**
   * Check if user is authenticated
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
   * SDK version
   */
  get version(): string {
    return "0.5.2";
  }

  // ========================================
  // Chainlist Methods
  // ========================================

  /**
   * Get RPC endpoints for a specific chain ID
   * Automatically filters out endpoints that require API keys
   *
   * @param chainId - The chain ID to get endpoints for
   * @returns Array of public RPC URLs (without API key requirements)
   *
   * @example
   * ```typescript
   * // Get Ethereum mainnet endpoints
   * const endpoints = await w3pk.getEndpoints(1)
   * console.log(endpoints)
   * // ["https://cloudflare-eth.com", "https://ethereum-rpc.publicnode.com", ...]
   * ```
   */
  async getEndpoints(chainId: number): Promise<string[]> {
    // Dynamically import to avoid bundling in all cases
    const { getEndpoints } = await import("../chainlist");
    return getEndpoints(chainId);
  }

  // ========================================
  // EIP-7702 Support
  // ========================================

  /**
   * Check if a network supports EIP-7702
   *
   * @param chainId - The chain ID to check
   * @returns True if the network supports EIP-7702, false otherwise
   *
   * @example
   * ```typescript
   * // Check Ethereum mainnet
   * const supported = w3pk.supportsEIP7702(1)
   * console.log(supported) // true
   *
   * // Check Sepolia testnet
   * console.log(w3pk.supportsEIP7702(11155111)) // true
   *
   * // Check Base
   * console.log(w3pk.supportsEIP7702(8453)) // true
   * ```
   */
  supportsEIP7702(chainId: number): boolean {
    // Sync import since this is a simple lookup, no async needed
    const { supportsEIP7702 } = require("../eip7702");
    return supportsEIP7702(chainId);
  }

  // ========================================
  // Utility Methods
  // ========================================

  /**
   * Internal logging
   */
  private log(message: string, level: "info" | "error" = "info"): void {
    if (this.config.debug) {
      const prefix = `[w3pk ${level.toUpperCase()}]`;
      if (level === "error") {
        console.error(prefix, message);
      } else {
        console.log(prefix, message);
      }
    }
  }

  /**
   * Clear all stored wallet data (use with caution!)
   */
  async clearAllData(): Promise<void> {
    await this.storage.clear();
    this.currentUser = null;
    this.currentMnemonic = null;

    if (this.config.onAuthStateChanged) {
      this.config.onAuthStateChanged(false, undefined);
    }

    this.log("All data cleared");
  }
}
