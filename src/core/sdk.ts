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
import { deriveEncryptionKey, encryptData } from "../wallet/crypto";
import { register } from "../auth/register";
import { authenticate, login } from "../auth/authenticate";
import type { Web3PasskeyConfig, InternalConfig } from "./config";
import { DEFAULT_CONFIG } from "./config";
import type { UserInfo, WalletInfo } from "../types";
import type { AuthResult } from "../auth/types";

export class Web3Passkey {
  private config: InternalConfig;
  private apiClient: ApiClient;
  private walletStorage: IndexedDBWalletStorage;
  private walletSigner: WalletSigner;
  private currentUser: UserInfo | null = null;
  private isAuthenticatedState: boolean = false;
  private isBrowser: boolean;

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
  // Public API - Authentication (Advanced)
  // ========================================

  /**
   * Register a new user with WebAuthn (advanced interface)
   * Requires manual WebAuthn credential management
   * For most use cases, use registerSimplified() instead
   *
   * @param username Username for the account
   * @param ethereumAddress Ethereum address from generated wallet
   * @param mnemonic BIP39 mnemonic to encrypt and store
   * @param credentialId WebAuthn credential ID (from registration response)
   * @param challenge Challenge used in registration
   */
  async register(options: {
    username: string;
    ethereumAddress: string;
    mnemonic: string;
    credentialId: string;
    challenge: string;
  }): Promise<void> {
    if (!this.isBrowser) {
      throw new Error(
        "Registration requires browser environment with WebAuthn support"
      );
    }

    try {
      const { username, ethereumAddress, mnemonic, credentialId, challenge } =
        options;

      // Step 1: Register with backend
      await register(this.apiClient, { username, ethereumAddress });

      // Step 2: Encrypt mnemonic with WebAuthn-derived key
      const encryptionKey = await deriveEncryptionKey(credentialId, challenge);
      const encryptedMnemonic = await encryptData(mnemonic, encryptionKey);

      // Step 3: Store encrypted mnemonic in IndexedDB
      await this.walletStorage.store({
        ethereumAddress,
        encryptedMnemonic,
        credentialId,
        challenge,
        createdAt: Date.now(),
      });

      // Step 4: Save auth state
      const user: UserInfo = {
        id: ethereumAddress,
        username,
        ethereumAddress,
      };
      this.saveAuthState(user);

      if (this.config.debug) {
        console.log("Registration successful for:", ethereumAddress);
      }
    } catch (error) {
      if (this.config.onError) {
        this.config.onError(error as any);
      }
      throw error;
    }
  }

  /**
   * Register a new user with WebAuthn (simplified interface)
   * Handles the complete registration flow internally
   * Automatically generates wallet if not provided
   *
   * @param username Username for the account
   * @param ethereumAddress Optional: Ethereum address (will generate if not provided)
   * @param mnemonic Optional: BIP39 mnemonic (will generate if not provided)
   * @returns Object containing ethereumAddress and mnemonic (only if generated)
   */
  async registerSimplified(options: {
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

      // Step 6: Save auth state
      const user: UserInfo = {
        id: ethereumAddress,
        username,
        ethereumAddress,
      };
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
   * Authenticate with Ethereum address
   */
  async authenticate(ethereumAddress: string): Promise<AuthResult> {
    if (!this.isBrowser) {
      throw new Error(
        "Authentication requires browser environment with WebAuthn support"
      );
    }

    try {
      const result = await authenticate(this.apiClient, ethereumAddress);

      if (result.verified && result.user) {
        const user: UserInfo = {
          id: result.user.id,
          username: result.user.username,
          ethereumAddress: result.user.ethereumAddress,
        };
        this.saveAuthState(user);

        if (this.config.debug) {
          console.log("Authentication successful for:", ethereumAddress);
        }
      }

      return result;
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
      const result = await login(this.apiClient);

      if (result.verified && result.user) {
        const user: UserInfo = {
          id: result.user.id,
          username: result.user.username,
          ethereumAddress: result.user.ethereumAddress,
        };
        this.saveAuthState(user);

        if (this.config.debug) {
          console.log(
            "Usernameless authentication successful for:",
            result.user.ethereumAddress
          );
        }
      }

      return result;
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
   * Sign a message with encrypted wallet (advanced interface)
   * Requires fresh WebAuthn authentication credentials
   * For most use cases, use signMessageSimplified() instead
   *
   * @param message Message to sign
   * @param credentialId WebAuthn credential ID (from fresh auth)
   * @param challenge Challenge from fresh auth
   */
  async signMessage(
    message: string,
    credentialId: string,
    challenge: string
  ): Promise<string> {
    if (!this.isBrowser) {
      throw new Error("Message signing requires browser environment");
    }

    if (!this.currentUser) {
      throw new Error("Not authenticated");
    }

    try {
      const signature = await this.walletSigner.signMessage(
        this.currentUser.ethereumAddress,
        message,
        credentialId,
        challenge
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

  /**
   * Sign a message with encrypted wallet (simplified interface)
   * Handles fresh WebAuthn authentication internally
   *
   * @param message Message to sign
   */
  async signMessageSimplified(message: string): Promise<string> {
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
    return "0.1.0";
  }

  /**
   * Check if running in browser environment
   */
  get isBrowserEnvironment(): boolean {
    return this.isBrowser;
  }
}
