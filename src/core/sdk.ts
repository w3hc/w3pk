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
import { generateBIP39Wallet } from "../wallet/generate";
import {
  deriveEncryptionKey,
  encryptData,
  decryptData,
} from "../wallet/crypto";
import { StealthAddressModule } from "../stealth";
import type {
  Web3PasskeyConfig,
  InternalConfig,
  StealthAddressConfig,
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
  private walletStorage: IndexedDBWalletStorage;
  private walletSigner: WalletSigner;
  private currentUser: UserInfo | null = null;
  private isAuthenticatedState: boolean = false;
  private isBrowser: boolean;
  private stealthAddresses: StealthAddressModule | null = null;

  constructor(config: Web3PasskeyConfig) {
    // Check if running in browser
    this.isBrowser =
      typeof window !== "undefined" && typeof localStorage !== "undefined";

    // Merge with defaults
    this.config = {
      ...DEFAULT_CONFIG,
      ...config,
      timeout: config.timeout ?? DEFAULT_CONFIG.timeout!,
      debug: config.debug ?? DEFAULT_CONFIG.debug!,
    } as InternalConfig;

    // Initialize components
    this.apiClient = new ApiClient(this.config.apiBaseUrl, this.config.timeout);
    this.walletStorage = new IndexedDBWalletStorage();
    this.walletSigner = new WalletSigner(this.walletStorage);

    // Initialize stealth addresses if configured
    if (config.stealthAddresses) {
      this.stealthAddresses = new StealthAddressModule(
        config.stealthAddresses,
        this.getMnemonic.bind(this)
      );
    }

    // Initialize storage only in browser
    if (this.isBrowser) {
      this.walletStorage.init().catch((error) => {
        if (this.config.debug) {
          console.error("Failed to initialize wallet storage:", error);
        }
      });

      // Load persisted auth state
      this.loadAuthState();
    } else if (this.config.debug) {
      console.warn(
        "w3pk: Running in non-browser environment, some features disabled"
      );
    }
  }

  // ========================================
  // Auth State Management
  // ========================================

  private loadAuthState(): void {
    if (!this.isBrowser) return;

    try {
      const storedUser = localStorage.getItem("w3pk_user");
      const storedAuth = localStorage.getItem("w3pk_authenticated");

      if (storedUser && storedAuth === "true") {
        this.currentUser = JSON.parse(storedUser);
        this.isAuthenticatedState = true;
        this.notifyAuthStateChange(true, this.currentUser ?? undefined);
      }
    } catch (error) {
      if (this.config.debug) {
        console.error("Failed to load auth state:", error);
      }
      this.clearAuthState();
    }
  }

  private saveAuthState(user: UserInfo): void {
    if (!this.isBrowser) {
      console.warn("w3pk: Cannot save auth state in non-browser environment");
      return;
    }

    try {
      localStorage.setItem("w3pk_user", JSON.stringify(user));
      localStorage.setItem("w3pk_authenticated", "true");
      this.currentUser = user;
      this.isAuthenticatedState = true;
      this.notifyAuthStateChange(true, user);
    } catch (error) {
      if (this.config.debug) {
        console.error("Failed to save auth state:", error);
      }
    }
  }

  private clearAuthState(): void {
    if (!this.isBrowser) return;

    try {
      localStorage.removeItem("w3pk_user");
      localStorage.removeItem("w3pk_authenticated");
    } catch (error) {
      if (this.config.debug) {
        console.error("Failed to clear auth state:", error);
      }
    }

    this.currentUser = null;
    this.isAuthenticatedState = false;
    this.notifyAuthStateChange(false);
  }

  private notifyAuthStateChange(
    isAuthenticated: boolean,
    user?: UserInfo
  ): void {
    if (this.config.onAuthStateChanged) {
      this.config.onAuthStateChanged(isAuthenticated, user);
    }
  }

  private createUserInfo(username: string, ethereumAddress: string): UserInfo {
    return {
      id: ethereumAddress,
      username,
      displayName: username,
      ethereumAddress,
    };
  }

  /**
   * Get mnemonic for current authenticated user
   * Used by stealth address module
   */
  private async getMnemonic(): Promise<string | null> {
    if (!this.isBrowser || !this.currentUser) {
      return null;
    }

    try {
      // Get encrypted wallet data
      const walletData = await this.walletStorage.retrieve(
        this.currentUser.ethereumAddress
      );
      if (!walletData) {
        return null;
      }

      // Derive encryption key from stored credentials
      const encryptionKey = await deriveEncryptionKey(
        walletData.credentialId,
        walletData.challenge
      );

      // Decrypt mnemonic
      return await decryptData(walletData.encryptedMnemonic, encryptionKey);
    } catch (error) {
      if (this.config.debug) {
        console.error("Failed to get mnemonic:", error);
      }
      return null;
    }
  }

  // ========================================
  // Public API - Wallet
  // ========================================

  /**
   * Generate a new BIP39 wallet
   * @returns Wallet info with mnemonic (user MUST backup)
   */
  async generateWallet(): Promise<WalletInfo> {
    try {
      const wallet = generateBIP39Wallet();

      if (this.config.debug) {
        console.log("Wallet generated:", wallet.address);
      }

      return wallet;
    } catch (error) {
      if (this.config.onError) {
        this.config.onError(error as any);
      }
      throw error;
    }
  }

  /**
   * Check if wallet exists for current user
   */
  async hasWallet(): Promise<boolean> {
    if (!this.isBrowser) {
      console.warn(
        "w3pk: Wallet storage not available in non-browser environment"
      );
      return false;
    }

    if (!this.currentUser) {
      return false;
    }

    try {
      return await this.walletSigner.hasWallet(
        this.currentUser.ethereumAddress
      );
    } catch (error) {
      if (this.config.debug) {
        console.error("Failed to check wallet existence:", error);
      }
      return false;
    }
  }

  // ========================================
  // Public API - Authentication
  // ========================================

  /**
   * Register a new user with WebAuthn
   * Handles the complete registration flow internally
   * Automatically generates wallet if not provided
   *
   * @param username Username for the account
   * @param ethereumAddress Optional: Ethereum address (will generate if not provided)
   * @param mnemonic Optional: BIP39 mnemonic (will generate if not provided)
   * @returns Object containing ethereumAddress and mnemonic (only if generated)
   */
  async register(options: {
    username: string;
    ethereumAddress?: string;
    mnemonic?: string;
  }): Promise<{ ethereumAddress: string; mnemonic?: string }> {
    if (!this.isBrowser) {
      throw new Error(
        "Registration requires browser environment with WebAuthn support"
      );
    }

    try {
      const { username } = options;
      let { ethereumAddress, mnemonic } = options;

      // Generate wallet if not provided
      if (!ethereumAddress || !mnemonic) {
        const wallet = generateBIP39Wallet();
        ethereumAddress = wallet.address;
        mnemonic = wallet.mnemonic;
      }

      // Step 1: Begin registration - get WebAuthn options from server
      const beginResponse = await this.apiClient.post(
        "/webauthn/register/begin",
        {
          username,
          ethereumAddress,
        }
      );

      if (!beginResponse.success || !beginResponse.data) {
        throw new Error("Failed to get registration options from server");
      }

      // Handle different response formats
      const webauthnOptions = beginResponse.data.options || beginResponse.data;

      // Step 2: Perform WebAuthn registration (browser prompt)
      const credential = await startRegistration(webauthnOptions);

      // Step 3: Encrypt mnemonic with WebAuthn-derived key
      const encryptionKey = await deriveEncryptionKey(
        credential.id,
        webauthnOptions.challenge
      );
      const encryptedMnemonic = await encryptData(mnemonic, encryptionKey);

      // Step 4: Store encrypted mnemonic in IndexedDB
      await this.walletStorage.store({
        ethereumAddress,
        encryptedMnemonic,
        credentialId: credential.id,
        challenge: webauthnOptions.challenge,
        createdAt: Date.now(),
      });

      // Step 5: Complete registration with server
      const completeResponse = await this.apiClient.post(
        "/webauthn/register/complete",
        {
          ethereumAddress,
          response: credential,
        }
      );

      if (!completeResponse.success) {
        throw new Error("Registration verification failed");
      }

      // Step 6: Save auth state with displayName
      const user = this.createUserInfo(username, ethereumAddress);
      this.saveAuthState(user);

      if (this.config.debug) {
        console.log("Registration successful for:", ethereumAddress);
      }

      // Return the wallet info (mnemonic only if we generated it)
      return {
        ethereumAddress,
        mnemonic: options.mnemonic ? undefined : mnemonic,
      };
    } catch (error) {
      if (this.config.onError) {
        this.config.onError(error as any);
      }
      throw error;
    }
  }

  /**
   * Authenticate without username (usernameless flow)
   */
  async login(): Promise<AuthResult> {
    if (!this.isBrowser) {
      throw new Error(
        "Authentication requires browser environment with WebAuthn support"
      );
    }

    try {
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

      // Handle different response formats
      const webauthnOptions = beginResponse.data.options || beginResponse.data;

      // Step 2: WebAuthn authentication
      const credential = await startAuthentication(webauthnOptions);

      // Step 3: Complete authentication
      const completeResponse = await this.apiClient.post(
        "/webauthn/authenticate/usernameless/complete",
        { response: credential }
      );

      if (!completeResponse.success) {
        throw new Error("Usernameless authentication verification failed");
      }

      const serverUser = completeResponse.data?.user;
      if (!serverUser) {
        throw new Error("No user data received from server");
      }

      // Create UserInfo with displayName
      const user = this.createUserInfo(
        serverUser.username,
        serverUser.ethereumAddress || serverUser.id
      );
      this.saveAuthState(user);

      if (this.config.debug) {
        console.log(
          "Usernameless authentication successful for:",
          user.ethereumAddress
        );
      }

      return {
        verified: true,
        user,
      };
    } catch (error) {
      if (this.config.onError) {
        this.config.onError(error as any);
      }
      throw error;
    }
  }

  /**
   * Logout current user
   */
  logout(): void {
    this.clearAuthState();

    if (this.config.debug) {
      console.log("User logged out");
    }
  }

  // ========================================
  // Public API - Message Signing
  // ========================================

  /**
   * Sign a message with encrypted wallet
   * Handles fresh WebAuthn authentication internally
   *
   * @param message Message to sign
   */
  async signMessage(message: string): Promise<string> {
    if (!this.isBrowser) {
      throw new Error("Message signing requires browser environment");
    }

    if (!this.currentUser) {
      throw new Error("Not authenticated");
    }

    try {
      // Step 1: Check if wallet exists
      const walletData = await this.walletStorage.retrieve(
        this.currentUser.ethereumAddress
      );
      if (!walletData) {
        throw new Error(
          "No wallet found on this device. Please register to create a new wallet."
        );
      }

      // Step 2: Request fresh WebAuthn authentication
      if (this.config.debug) {
        console.log("Requesting WebAuthn authentication for signing...");
      }

      const beginResponse = await this.apiClient.post(
        "/webauthn/authenticate/usernameless/begin",
        {}
      );

      if (!beginResponse.success || !beginResponse.data) {
        throw new Error("Failed to begin authentication for signing");
      }

      // Handle different response formats
      const webauthnOptions = beginResponse.data.options || beginResponse.data;

      // Step 3: Perform WebAuthn authentication (browser prompt)
      const credential = await startAuthentication(webauthnOptions);

      // Step 4: Verify authentication with server
      const completeResponse = await this.apiClient.post(
        "/webauthn/authenticate/usernameless/complete",
        { response: credential }
      );

      if (!completeResponse.success) {
        throw new Error("Authentication verification failed for signing");
      }

      // Step 5: Use the authenticated credentials to sign
      const signature = await this.walletSigner.signMessage(
        this.currentUser.ethereumAddress,
        message,
        walletData.credentialId,
        walletData.challenge
      );

      if (this.config.debug) {
        console.log("Message signed successfully");
      }

      return signature;
    } catch (error) {
      if (this.config.onError) {
        this.config.onError(error as any);
      }
      throw error;
    }
  }

  // ========================================
  // Public API - Getters
  // ========================================

  /**
   * Check if user is authenticated
   */
  get isAuthenticated(): boolean {
    return this.isAuthenticatedState;
  }

  /**
   * Get current user info
   */
  get user(): UserInfo | null {
    return this.currentUser;
  }

  /**
   * Get SDK version
   */
  get version(): string {
    return "0.4.0";
  }

  /**
   * Check if running in browser environment
   */
  get isBrowserEnvironment(): boolean {
    return this.isBrowser;
  }

  /**
   * Get stealth address module (if configured)
   */
  get stealth(): StealthAddressModule | null {
    return this.stealthAddresses;
  }
}
