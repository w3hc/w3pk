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
import { ZKProofModule } from "../zk";
import type {
  Web3PasskeyConfig,
  InternalConfig,
  StealthAddressConfig,
} from "./config";
import { DEFAULT_CONFIG } from "./config";
import type { UserInfo, WalletInfo } from "../types";
import type { ZKProofConfig } from "../zk/types";

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
  private zkModule?: ZKProofModule;
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

    // Initialize ZK module if configured
    if (this.config.zkProofs) {
      this.zkModule = new ZKProofModule(this.config.zkProofs);
    }

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
      const { username, ethereumAddress } = options;

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
  get zk(): ZKProofModule | undefined {
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
   */
  enableZKProofs(config: ZKProofConfig = {}): void {
    if (!this.zkModule) {
      this.zkModule = new ZKProofModule(config);
    }
  }

  // ========================================
  // Convenience Methods for Common ZK Patterns
  // ========================================

  /**
   * Prove membership in a verified user set
   * Useful for: "Prove I'm a verified user without revealing my identity"
   */
  async proveVerifiedMembership(
    userSet: string[],
    userIndex: number
  ): Promise<any> {
    if (!this.zkModule) {
      throw new Error("ZK proofs not enabled. Call enableZKProofs() first.");
    }

    const { buildMerkleTree, generateMerkleProof } = await import(
      "../zk/utils"
    );

    // Build merkle tree from user set
    const { root, tree } = await buildMerkleTree(userSet);

    // Generate proof for this user
    const { pathIndices, pathElements } = generateMerkleProof(tree, userIndex);

    return this.zkModule.proveMembership({
      value: userSet[userIndex],
      pathIndices,
      pathElements,
      root,
    });
  }

  /**
   * Prove wallet balance exceeds threshold
   * Useful for: "Prove I have > $1000 without revealing exact balance"
   */
  async proveBalanceThreshold(
    balance: bigint,
    threshold: bigint
  ): Promise<any> {
    if (!this.zkModule) {
      throw new Error("ZK proofs not enabled. Call enableZKProofs() first.");
    }

    const { generateBlinding } = await import("../zk/utils");
    const blinding = generateBlinding();
    const commitment = await this.zkModule.createCommitment(balance, blinding);

    return this.zkModule.proveThreshold({
      value: balance,
      blinding,
      threshold,
      commitment,
    });
  }

  /**
   * Prove age is within valid range
   * Useful for: "Prove I'm 18-65 without revealing exact age"
   */
  async proveAgeRange(
    age: bigint,
    minAge: bigint,
    maxAge: bigint
  ): Promise<any> {
    if (!this.zkModule) {
      throw new Error("ZK proofs not enabled. Call enableZKProofs() first.");
    }

    const { generateBlinding } = await import("../zk/utils");
    const blinding = generateBlinding();
    const commitment = await this.zkModule.createCommitment(age, blinding);

    return this.zkModule.proveRange({
      value: age,
      blinding,
      min: minAge,
      max: maxAge,
      commitment,
    });
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
    return "0.5.1";
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
