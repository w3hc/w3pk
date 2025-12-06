/**
 * Main Web3Passkey SDK
 *
 * SECURITY MODEL:
 * - Master mnemonic never exposed to applications
 * - Applications access only origin-specific derived wallets
 * - Three security modes for origin-centric derivation:
 *   - STANDARD: Address only (no private key), persistent sessions allowed
 *   - STRICT: Address only (no private key), no persistent sessions
 *   - YOLO: Full access (address + private key), persistent sessions allowed
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
  DEFAULT_MODE,
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
import type { UserInfo, WalletInfo, SecurityMode, SigningMethod } from "../types";
import { AuthenticationError, WalletError } from "./errors";
import { getEndpoints } from "../chainlist";
import { supportsEIP7702 } from "../eip7702";

export class Web3Passkey {
  private config: InternalConfig;
  private walletStorage: IndexedDBWalletStorage;
  private currentUser: UserInfo | null = null;
  private currentWallet: WalletInfo | null = null;
  private sessionManager: SessionManager;
  private currentSecurityMode: SecurityMode = 'STANDARD'; // Track current security mode

  public stealth?: StealthAddressModule;
  private zkModule?: any;

  constructor(config: Web3PasskeyConfig = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config } as InternalConfig;
    this.walletStorage = new IndexedDBWalletStorage();

    // Initialize session manager with persistent session config
    const persistentSessionConfig = {
      ...DEFAULT_CONFIG.persistentSession,
      ...config.persistentSession,
    };
    this.sessionManager = new SessionManager(
      config.sessionDuration || 1,
      persistentSessionConfig
    );

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
   * @param securityMode - Security mode to use for session persistence
   */
  private async getMnemonicFromSession(
    forceAuth: boolean = false,
    securityMode?: SecurityMode
  ): Promise<string> {
    const effectiveMode = securityMode || this.currentSecurityMode;

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

    await this.sessionManager.startSession(
      mnemonic,
      walletData.credentialId,
      this.currentUser.ethereumAddress,
      publicKey,
      effectiveMode
    );

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

      const storage = new (await import("../auth/storage")).CredentialStorage();
      const credential = await storage.getCredentialByAddress(ethereumAddress);

      this.currentUser = {
        id: ethereumAddress,
        username: options.username,
        displayName: options.username,
        ethereumAddress,
        credentialId: credential?.id || '',
      };

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

      await this.sessionManager.startSession(
        mnemonic,
        credentialId,
        ethereumAddress,
        publicKey,
        'STANDARD' // Default security mode for register
      );

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
   * Attempts to restore from persistent session if enabled
   *
   * If requireReauth is false and a valid persistent session exists,
   * the user will be logged in silently without a WebAuthn prompt.
   */
  async login(): Promise<UserInfo> {
    try {
      // STEP 1: Try silent restore if requireReauth is false
      const silentRestore = await this.sessionManager.attemptSilentRestore();

      if (silentRestore) {
        // Successfully restored session without WebAuthn prompt
        // Update username from credential storage
        const storage = new (await import("../auth/storage")).CredentialStorage();
        const credential = await storage.getCredentialById(silentRestore.credentialId);

        this.currentUser = {
          id: silentRestore.ethereumAddress,
          username: credential?.username || silentRestore.ethereumAddress,
          displayName: credential?.username || silentRestore.ethereumAddress,
          ethereumAddress: silentRestore.ethereumAddress,
          credentialId: silentRestore.credentialId,
        };

        // Verify wallet exists
        const walletData = await this.walletStorage.retrieve(
          this.currentUser.ethereumAddress
        );

        if (!walletData) {
          // Wallet was deleted but session still exists - clear session and retry with auth
          await this.sessionManager.clearSession();
          return this.login(); // Retry with authentication
        }

        this.config.onAuthStateChanged?.(true, this.currentUser);
        return this.currentUser;
      }

      // STEP 2: No silent restore - proceed with WebAuthn authentication
      const result = await login();

      if (!result.verified || !result.user) {
        throw new AuthenticationError("Login failed");
      }

      this.currentUser = {
        id: result.user.ethereumAddress,
        username: result.user.username,
        displayName: result.user.username,
        ethereumAddress: result.user.ethereumAddress,
        credentialId: result.user.credentialId,
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

      // Try to restore from persistent session first (if requireReauth is true)
      const restoredMnemonic = await this.sessionManager.restoreFromPersistentStorage(
        this.currentUser.ethereumAddress,
        walletData.credentialId,
        publicKey || ''
      );

      let mnemonic: string;
      if (restoredMnemonic) {
        // Successfully restored from persistent session
        mnemonic = restoredMnemonic;
      } else {
        // Decrypt from wallet storage (requires WebAuthn authentication)
        const encryptionKey = await deriveEncryptionKeyFromWebAuthn(
          walletData.credentialId,
          publicKey
        );

        mnemonic = await decryptData(
          walletData.encryptedMnemonic,
          encryptionKey
        );

        // Start new session with persistence
        await this.sessionManager.startSession(
          mnemonic,
          walletData.credentialId,
          this.currentUser.ethereumAddress,
          publicKey,
          'STANDARD' // Default security mode
        );
      }

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
    await this.sessionManager.clearSession();
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
   * SECURITY MODES:
   * - STANDARD (default): Address only (no private key), persistent sessions allowed
   * - STRICT: Address only (no private key), no persistent sessions (requires auth each time)
   * - YOLO: Full access (address + private key), persistent sessions allowed
   *
   * @param mode - Security mode for derivation (default: "STANDARD")
   * @param tag - Tag for derivation (default: "MAIN")
   * @param options.requireAuth - Force fresh authentication
   * @param options.origin - Override origin URL (testing only)
   *
   * @example
   * // Default: STANDARD mode with MAIN tag
   * const wallet = await w3pk.deriveWallet()
   *
   * // STRICT mode (no sessions)
   * const strictWallet = await w3pk.deriveWallet('STRICT')
   *
   * // YOLO mode with custom tag
   * const yoloWallet = await w3pk.deriveWallet('YOLO', 'GAMING')
   */
  async deriveWallet(
    mode?: SecurityMode,
    tag?: string,
    options?: { requireAuth?: boolean; origin?: string }
  ): Promise<WalletInfo & { index?: number; origin?: string; mode?: SecurityMode; tag?: string; publicKey?: string }> {
    try {
      if (!this.currentUser) {
        throw new WalletError("Must be authenticated to derive wallet");
      }

      const effectiveMode = mode || DEFAULT_MODE;
      const effectiveTag = tag || DEFAULT_TAG;
      const origin = options?.origin || getCurrentOrigin();

      console.log('[SDK] deriveWallet called with:', { mode, tag, effectiveMode, effectiveTag });

      // Track security mode for session management
      this.currentSecurityMode = effectiveMode;

      // PRIMARY mode: Use WebAuthn P-256 public key directly (EIP-7951)
      console.log('[SDK] Checking PRIMARY mode:', effectiveMode, effectiveMode === 'PRIMARY', typeof effectiveMode);
      if (effectiveMode === 'PRIMARY') {
        console.log('[SDK] Entering PRIMARY mode branch');
        const { CredentialStorage } = await import("../auth/storage");
        const { deriveAddressFromP256PublicKey } = await import("../wallet/origin-derivation");

        const storage = new CredentialStorage();
        const credential = await storage.getCredentialById(this.currentUser.credentialId);

        if (!credential || !credential.publicKey) {
          throw new WalletError("No WebAuthn credential found for PRIMARY mode");
        }

        const address = await deriveAddressFromP256PublicKey(credential.publicKey);

        return {
          address,
          origin,
          mode: effectiveMode,
          tag: effectiveTag,
          publicKey: credential.publicKey,
        };
      }

      // STRICT mode: always require authentication (no persistent sessions)
      const requireAuth = effectiveMode === 'STRICT' ? true : (options?.requireAuth || false);

      const mnemonic = await this.getMnemonicFromSession(requireAuth, effectiveMode);

      const derived = await getOriginSpecificAddress(mnemonic, origin, effectiveMode, effectiveTag);

      return {
        address: derived.address,
        privateKey: derived.privateKey,
        index: derived.index,
        origin: derived.origin,
        mode: derived.mode,
        tag: derived.tag,
      };
    } catch (error) {
      this.config.onError?.(error as any);
      throw new WalletError("Failed to derive wallet", error);
    }
  }

  /**
   * Get public address for a specific security mode and tag
   * Lightweight method that only returns the address without exposing private keys
   *
   * @param mode - Security mode (default: "STANDARD")
   * @param tag - Derivation tag (default: "MAIN")
   * @param options.origin - Override origin URL (testing only)
   * @returns The Ethereum address for this mode/tag combination
   *
   * @example
   * // Get PRIMARY address (P-256 from passkey)
   * const primaryAddr = await w3pk.getAddress("PRIMARY")
   *
   * // Get default STANDARD + MAIN address
   * const mainAddr = await w3pk.getAddress()
   *
   * // Get YOLO GAMING address
   * const gamingAddr = await w3pk.getAddress("YOLO", "GAMING")
   *
   * // Get STRICT address (will require authentication)
   * const strictAddr = await w3pk.getAddress("STRICT")
   */
  async getAddress(
    mode?: SecurityMode,
    tag?: string,
    options?: { origin?: string }
  ): Promise<string> {
    try {
      if (!this.currentUser) {
        throw new WalletError("Must be authenticated to get address");
      }

      const effectiveMode = mode || DEFAULT_MODE;
      const effectiveTag = tag || DEFAULT_TAG;
      const origin = options?.origin || getCurrentOrigin();

      // PRIMARY mode: Use WebAuthn P-256 public key directly (EIP-7951)
      if (effectiveMode === 'PRIMARY') {
        const { CredentialStorage } = await import("../auth/storage");
        const { deriveAddressFromP256PublicKey } = await import("../wallet/origin-derivation");

        const storage = new CredentialStorage();
        const credential = await storage.getCredentialById(this.currentUser.credentialId);

        if (!credential || !credential.publicKey) {
          throw new WalletError("No WebAuthn credential found for PRIMARY mode");
        }

        return await deriveAddressFromP256PublicKey(credential.publicKey);
      }

      // For other modes, derive from mnemonic
      // STRICT mode: always require authentication (no persistent sessions)
      const requireAuth = effectiveMode === 'STRICT' ? true : false;

      const mnemonic = await this.getMnemonicFromSession(requireAuth, effectiveMode);

      const derived = await getOriginSpecificAddress(mnemonic, origin, effectiveMode, effectiveTag);

      return derived.address;
    } catch (error) {
      this.config.onError?.(error as any);
      throw new WalletError("Failed to get address", error);
    }
  }

  /**
   * Export mnemonic (disabled for security)
   * Use createBackupFile() instead
   * @deprecated
   * @throws WalletError
   */
  async exportMnemonic(): Promise<string> {
    throw new WalletError(
      "exportMnemonic() disabled for security. Use createBackupFile() instead."
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

      await this.sessionManager.startSession(
        mnemonic.trim(),
        credentialId,
        this.currentUser.ethereumAddress,
        publicKey,
        'STANDARD' // Default security mode for importMnemonic
      );
    } catch (error) {
      this.config.onError?.(error as any);
      throw new WalletError("Failed to import mnemonic", error);
    }
  }

  /**
   * Sign message with wallet
   *
   * By default, signs with STANDARD mode + MAIN tag (origin-centric address).
   * You can specify a different mode and tag to sign from a specific derived address.
   *
   * @param message - Message to sign
   * @param options.mode - Security mode for derivation (default: "STANDARD")
   * @param options.tag - Tag for derivation (default: "MAIN")
   * @param options.requireAuth - Force fresh authentication
   * @param options.origin - Override origin URL (testing only)
   * @returns Signature result with address, mode, and tag information
   *
   * @example
   * // Default: Sign with STANDARD + MAIN address
   * const result = await w3pk.signMessage("Hello World")
   * console.log(result.signature) // The signature
   * console.log(result.address)   // Address that signed
   * console.log(result.mode)      // 'STANDARD'
   * console.log(result.tag)       // 'MAIN'
   *
   * // Sign with YOLO + GAMING address
   * const gamingResult = await w3pk.signMessage("Hello World", {
   *   mode: 'YOLO',
   *   tag: 'GAMING'
   * })
   * console.log(gamingResult.address) // Different address!
   *
   * // Sign with STRICT mode (requires auth every time)
   * const strictResult = await w3pk.signMessage("Hello World", {
   *   mode: 'STRICT'
   * })
   */
  async signMessage(
    message: string,
    options?: {
      mode?: SecurityMode;
      tag?: string;
      requireAuth?: boolean;
      origin?: string;
      signingMethod?: SigningMethod;
      // EIP-712 specific options
      eip712Domain?: Record<string, any>;
      eip712Types?: Record<string, Array<{ name: string; type: string }>>;
      eip712PrimaryType?: string;
    }
  ): Promise<{
    signature: string;
    address: string;
    mode: SecurityMode;
    tag: string;
    origin: string;
  }> {
    try {
      if (!this.currentUser) {
        throw new WalletError("Must be authenticated to sign message");
      }

      const effectiveMode = options?.mode || DEFAULT_MODE;
      const effectiveTag = options?.tag || DEFAULT_TAG;
      const origin = options?.origin || getCurrentOrigin();
      const signingMethod = options?.signingMethod || 'EIP191';

      // Track security mode for session management
      this.currentSecurityMode = effectiveMode;

      // STRICT mode: always require authentication (no persistent sessions)
      const requireAuth = effectiveMode === 'STRICT' ? true : (options?.requireAuth || false);

      const mnemonic = await this.getMnemonicFromSession(requireAuth, effectiveMode);

      // Derive the wallet from the specified mode and tag
      const derived = await getOriginSpecificAddress(mnemonic, origin, effectiveMode, effectiveTag);

      const { Wallet } = await import("ethers");

      // If YOLO mode, we have the private key available
      let wallet: any;
      if (derived.privateKey) {
        wallet = new Wallet(derived.privateKey);
      } else {
        // For STANDARD/STRICT modes, derive from mnemonic at the specific index
        const { deriveWalletFromMnemonic } = await import("../wallet/generate");
        const { privateKey } = deriveWalletFromMnemonic(mnemonic, derived.index);
        wallet = new Wallet(privateKey);
      }

      let signature: string;

      // Handle different signing methods
      switch (signingMethod) {
        case 'EIP191':
          // Default behavior - EIP-191 compliant message signing
          signature = await wallet.signMessage(message);
          break;

        case 'SIWE':
          // SIWE (Sign-In with Ethereum) - EIP-4361 compliant
          // SIWE messages are signed with EIP-191 prefix (for EOA accounts)
          // The message should already be a properly formatted SIWE message
          signature = await wallet.signMessage(message);
          break;

        case 'EIP712':
          // EIP-712 typed data signing
          // Validate required options
          if (!options?.eip712Domain || !options?.eip712Types || !options?.eip712PrimaryType) {
            throw new WalletError("EIP712 signing requires eip712Domain, eip712Types, and eip712PrimaryType in options");
          }

          // Parse message as JSON if it's a string
          let typedDataMessage: Record<string, any>;
          try {
            typedDataMessage = typeof message === 'string' ? JSON.parse(message) : message;
          } catch (e) {
            throw new WalletError("EIP712 message must be valid JSON or an object");
          }

          // Sign typed data
          signature = await wallet.signTypedData(
            options.eip712Domain,
            options.eip712Types,
            typedDataMessage
          );
          break;

        case 'rawHash':
          // Sign raw 32-byte hash without EIP-191 prefix
          // Useful for signing pre-computed EIP-712 hashes (e.g., Safe transactions)
          const { SigningKey } = await import("ethers");

          // Validate that the message is a 32-byte hash
          let hashToSign = message;
          if (hashToSign.startsWith('0x')) {
            hashToSign = hashToSign.slice(2);
          }

          if (hashToSign.length !== 64) {
            throw new WalletError("rawHash signing method requires a 32-byte hash (64 hex characters)");
          }

          // Get the private key from the wallet
          const signingKey = new SigningKey(wallet.privateKey);

          // Sign the raw hash directly without EIP-191 prefix
          const rawSignature = signingKey.sign('0x' + hashToSign);
          signature = rawSignature.serialized;
          break;

        default:
          throw new WalletError(`Unsupported signing method: ${signingMethod}`);
      }

      return {
        signature,
        address: derived.address,
        mode: derived.mode,
        tag: derived.tag,
        origin: derived.origin,
      };
    } catch (error) {
      this.config.onError?.(error as any);
      throw new WalletError("Failed to sign message", error);
    }
  }

  /**
   * Sign a message using WebAuthn (P-256) for PRIMARY mode
   * This method uses the passkey directly for signing instead of a private key
   *
   * @param message - The message to sign
   * @returns Signature details including r, s components and the hash that was signed
   *
   * @example
   * const result = await w3pk.signMessageWithPasskey("Hello World")
   * console.log(result.signature) // { r: "0x...", s: "0x..." }
   * console.log(result.messageHash) // Original message hash
   * console.log(result.signedHash) // WebAuthn signed hash
   * console.log(result.address) // PRIMARY mode address
   */
  async signMessageWithPasskey(message: string): Promise<{
    signature: { r: string; s: string };
    messageHash: string;
    signedHash: string;
    address: string;
    publicKey: { qx: string; qy: string };
  }> {
    try {
      if (!this.currentUser) {
        throw new WalletError("Must be authenticated to sign message");
      }

      const { extractRS } = await import("../utils/crypto");
      const { base64UrlDecode } = await import("../utils/base64");

      // Hash the message
      const messageHash = await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(message)
      );
      const h = '0x' + Buffer.from(messageHash).toString('hex');

      // Generate challenge from message hash
      const challengeBytes = new Uint8Array(Buffer.from(h.slice(2), 'hex'));

      // Get credential ID from current user
      const credentialId = this.currentUser.credentialId;
      if (!credentialId) {
        throw new WalletError('Credential ID not found in user object');
      }

      // Request WebAuthn signature
      const assertionOptions: PublicKeyCredentialRequestOptions = {
        challenge: challengeBytes,
        rpId: window.location.hostname,
        allowCredentials: [
          {
            id: base64UrlDecode(credentialId),
            type: 'public-key',
            transports: ['internal', 'hybrid', 'usb', 'nfc', 'ble'],
          },
        ],
        userVerification: 'required',
        timeout: 60000,
      };

      const assertion = (await navigator.credentials.get({
        publicKey: assertionOptions,
      })) as PublicKeyCredential | null;

      if (!assertion || !assertion.response) {
        throw new WalletError('WebAuthn signature failed');
      }

      const response = assertion.response as AuthenticatorAssertionResponse;

      // WebAuthn signs: SHA-256(authenticatorData || SHA-256(clientDataJSON))
      const authenticatorData = new Uint8Array(response.authenticatorData);
      const clientDataJSON = new Uint8Array(response.clientDataJSON);
      const clientDataHash = await crypto.subtle.digest('SHA-256', clientDataJSON);

      // Concatenate authenticatorData + clientDataHash
      const signedData = new Uint8Array(authenticatorData.length + clientDataHash.byteLength);
      signedData.set(authenticatorData, 0);
      signedData.set(new Uint8Array(clientDataHash), authenticatorData.length);

      // Hash the concatenation to get what was actually signed
      const actualMessageHash = await crypto.subtle.digest('SHA-256', signedData.buffer);
      const actualH = '0x' + Buffer.from(actualMessageHash).toString('hex');

      // Extract r and s from the DER-encoded signature
      const signature = new Uint8Array(response.signature);
      const { r, s } = extractRS(signature);

      // Get public key coordinates
      const { CredentialStorage } = await import("../auth/storage");
      const storage = new CredentialStorage();
      const credential = await storage.getCredentialById(credentialId);

      if (!credential || !credential.publicKey) {
        throw new WalletError('No WebAuthn credential found for PRIMARY mode');
      }

      // Decode the public key to get x and y coordinates
      const { base64UrlToArrayBuffer } = await import("../utils/base64");
      const publicKeyBuffer = base64UrlToArrayBuffer(credential.publicKey);

      // Import the public key
      const publicKey = await crypto.subtle.importKey(
        'spki',
        publicKeyBuffer,
        {
          name: 'ECDSA',
          namedCurve: 'P-256',
        },
        true,
        ['verify']
      );

      // Export as JWK to get x and y coordinates
      const jwk = await crypto.subtle.exportKey('jwk', publicKey);

      if (!jwk.x || !jwk.y) {
        throw new WalletError('Invalid P-256 public key: missing x or y coordinates');
      }

      // Convert base64url x and y to hex (each is 32 bytes for P-256)
      const qx = '0x' + Buffer.from(base64UrlToArrayBuffer(jwk.x)).toString('hex');
      const qy = '0x' + Buffer.from(base64UrlToArrayBuffer(jwk.y)).toString('hex');

      // Derive address from public key
      const { deriveAddressFromP256PublicKey } = await import("../wallet/origin-derivation");
      const address = await deriveAddressFromP256PublicKey(credential.publicKey);

      return {
        signature: { r, s },
        messageHash: h,
        signedHash: actualH,
        address,
        publicKey: { qx, qy },
      };
    } catch (error) {
      this.config.onError?.(error as any);
      throw new WalletError("Failed to sign message with passkey", error);
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
   * Create simplified backup file
   * This backup can be used to:
   * - Restore wallet with existing passkey
   * - Register new passkey with this wallet
   * - Sync wallet across devices
   * - Split among guardians for social recovery
   *
   * @param encryptionType - 'password' (default), 'passkey', or 'hybrid'
   * @param password - Required for 'password' and 'hybrid' encryption
   */
  async createBackupFile(
    encryptionType: 'password' | 'passkey' | 'hybrid' = 'password',
    password?: string
  ): Promise<{ blob: Blob; filename: string }> {
    if (!this.currentUser) {
      throw new WalletError("Must be authenticated to create backup");
    }

    const mnemonic = await this.getMnemonicFromSession(true);

    const { BackupFileManager } = await import("../backup/backup-file");
    const manager = new BackupFileManager();

    let result;

    if (encryptionType === 'password') {
      if (!password) {
        throw new WalletError("Password required for password-based backup");
      }
      const { backupFile } = await manager.createPasswordBackup(
        mnemonic,
        this.currentUser.ethereumAddress,
        password
      );
      result = manager.createDownloadableBackup(backupFile);
    } else if (encryptionType === 'passkey') {
      // Get current credential info
      const walletData = await this.walletStorage.retrieve(
        this.currentUser.ethereumAddress
      );
      if (!walletData) {
        throw new WalletError("No wallet data found");
      }

      const storage = new (await import("../auth/storage")).CredentialStorage();
      const credential = await storage.getCredentialById(walletData.credentialId);
      if (!credential) {
        throw new WalletError("Credential not found");
      }

      const { backupFile } = await manager.createPasskeyBackup(
        mnemonic,
        this.currentUser.ethereumAddress,
        credential.id,
        credential.publicKey
      );
      result = manager.createDownloadableBackup(backupFile);
    } else if (encryptionType === 'hybrid') {
      if (!password) {
        throw new WalletError("Password required for hybrid backup");
      }

      const walletData = await this.walletStorage.retrieve(
        this.currentUser.ethereumAddress
      );
      if (!walletData) {
        throw new WalletError("No wallet data found");
      }

      const storage = new (await import("../auth/storage")).CredentialStorage();
      const credential = await storage.getCredentialById(walletData.credentialId);
      if (!credential) {
        throw new WalletError("Credential not found");
      }

      const { backupFile } = await manager.createHybridBackup(
        mnemonic,
        this.currentUser.ethereumAddress,
        password,
        credential.id,
        credential.publicKey
      );
      result = manager.createDownloadableBackup(backupFile);
    } else {
      throw new WalletError(`Unknown encryption type: ${encryptionType}`);
    }

    return result;
  }

  /**
   * Set up social recovery by splitting backup file among guardians
   * Uses Shamir Secret Sharing to split the backup - requires M-of-N guardians to recover
   *
   * @param guardians - List of guardian names/emails
   * @param threshold - Number of guardians required to recover (M-of-N)
   * @param password - Optional password for additional encryption layer
   */
  async setupSocialRecovery(
    guardians: { name: string; email?: string }[],
    threshold: number,
    password?: string
  ): Promise<{
    guardianShares: any[];
    setupComplete: boolean;
  }> {
    if (!this.currentUser) {
      throw new WalletError("Must be authenticated to set up social recovery");
    }

    const mnemonic = await this.getMnemonicFromSession(true);

    // Create backup file (password-protected if password provided)
    const { BackupFileManager } = await import("../backup/backup-file");
    const backupManager = new BackupFileManager();

    const { backupFile } = password
      ? await backupManager.createPasswordBackup(mnemonic, this.currentUser.ethereumAddress, password)
      : await backupManager.createPasskeyBackup(
          mnemonic,
          this.currentUser.ethereumAddress,
          (await this.walletStorage.retrieve(this.currentUser.ethereumAddress))!.credentialId,
          (await (await import("../auth/storage")).CredentialStorage.prototype.getCredentialById.call(
            new (await import("../auth/storage")).CredentialStorage(),
            (await this.walletStorage.retrieve(this.currentUser.ethereumAddress))!.credentialId
          ))!.publicKey
        );

    // Split backup among guardians
    const { SocialRecovery } = await import("../recovery/backup-based-recovery");
    const recovery = new SocialRecovery();

    const setup = await recovery.splitAmongGuardians(
      backupFile,
      guardians,
      threshold
    );

    return {
      guardianShares: setup.guardianShares,
      setupComplete: true,
    };
  }

  /**
   * Generate guardian invitation document and QR code
   *
   * @param guardianShare - The guardian's share data
   * @param message - Optional custom message for the guardian
   */
  async generateGuardianInvite(
    guardianShare: any,
    message?: string
  ): Promise<{
    qrCodeDataURL?: string;
    shareDocument: string;
    downloadBlob: Blob;
    filename: string;
  }> {
    const { SocialRecovery } = await import("../recovery/backup-based-recovery");
    const recovery = new SocialRecovery();

    const invitation = await recovery.createGuardianInvitation(guardianShare, message);
    const download = recovery.createShareDownload(guardianShare);

    return {
      qrCodeDataURL: invitation.qrCodeDataURL,
      shareDocument: invitation.shareDocument,
      downloadBlob: download.blob,
      filename: download.filename,
    };
  }

  /**
   * Recover wallet from guardian shares
   * Combines M-of-N guardian shares to reconstruct the backup file
   *
   * @param shares - Array of guardian share objects (JSON strings or parsed objects)
   * @param password - Password to decrypt the backup (if password-protected)
   */
  async recoverFromGuardians(
    shares: Array<string | any>,
    password?: string
  ): Promise<{ mnemonic: string; ethereumAddress: string }> {
    const { SocialRecovery } = await import("../recovery/backup-based-recovery");
    const { BackupFileManager } = await import("../backup/backup-file");

    const recovery = new SocialRecovery();
    const backupManager = new BackupFileManager();

    // Parse shares if they're strings
    const parsedShares = shares.map(share =>
      typeof share === 'string' ? recovery.parseGuardianShare(share) : share
    );

    // Combine shares to recover backup file
    const backupFile = await recovery.recoverFromShares(parsedShares);

    // Decrypt backup file
    if (backupFile.encryptionMethod === 'password') {
      if (!password) {
        throw new WalletError('Password required to decrypt password-protected backup');
      }
      return backupManager.restoreWithPassword(backupFile, password);
    } else {
      throw new WalletError(
        'Passkey-encrypted backups not supported for guardian recovery. Use password-protected backups.'
      );
    }
  }

  /**
   * Restore wallet from backup file with existing passkey
   * Use case: User has passkey synced to this device
   *
   * After restoration, you can either:
   * - Use importMnemonic() to associate with current logged-in user
   * - Use registerWithBackupFile() to create new passkey for this wallet
   */
  async restoreFromBackupFile(
    backupData: string | Blob,
    password?: string
  ): Promise<{ mnemonic: string; ethereumAddress: string }> {
    const { BackupFileManager } = await import("../backup/backup-file");
    const manager = new BackupFileManager();

    const backupFile = await manager.parseBackupFile(backupData);

    // Determine which restore method to use based on encryption type
    if (backupFile.encryptionMethod === 'password') {
      if (!password) {
        throw new WalletError("Password required to restore password-encrypted backup");
      }
      return manager.restoreWithPassword(backupFile, password);
    } else if (backupFile.encryptionMethod === 'passkey') {
      // Need to authenticate with passkey first
      if (!this.currentUser) {
        throw new WalletError(
          "Must be logged in with passkey to restore passkey-encrypted backup. Call login() first."
        );
      }

      const walletData = await this.walletStorage.retrieve(
        this.currentUser.ethereumAddress
      );
      if (!walletData) {
        throw new WalletError("No wallet data found for current user");
      }

      const storage = new (await import("../auth/storage")).CredentialStorage();
      const credential = await storage.getCredentialById(walletData.credentialId);
      if (!credential) {
        throw new WalletError("Credential not found");
      }

      return manager.restoreWithExistingPasskey(
        backupFile,
        credential.id,
        credential.publicKey
      );
    } else if (backupFile.encryptionMethod === 'hybrid') {
      if (!password) {
        throw new WalletError("Password required to restore hybrid backup");
      }

      if (!this.currentUser) {
        throw new WalletError(
          "Must be logged in with passkey to restore hybrid backup. Call login() first."
        );
      }

      const walletData = await this.walletStorage.retrieve(
        this.currentUser.ethereumAddress
      );
      if (!walletData) {
        throw new WalletError("No wallet data found for current user");
      }

      const storage = new (await import("../auth/storage")).CredentialStorage();
      const credential = await storage.getCredentialById(walletData.credentialId);
      if (!credential) {
        throw new WalletError("Credential not found");
      }

      return manager.restoreWithHybrid(
        backupFile,
        password,
        credential.id,
        credential.publicKey
      );
    } else {
      throw new WalletError(`Unknown encryption method: ${backupFile.encryptionMethod}`);
    }
  }

  /**
   * Register new passkey with wallet from backup file
   * Use case: Fresh device, user has backup file but no passkey yet
   *
   * This creates a NEW passkey and associates it with the wallet from the backup
   *
   * @param backupData - Backup file (JSON string or Blob)
   * @param password - Password to decrypt the backup
   * @param username - Username for the new passkey
   */
  async registerWithBackupFile(
    backupData: string | Blob,
    password: string,
    username: string
  ): Promise<{ address: string; username: string }> {
    const { BackupFileManager } = await import("../backup/backup-file");
    const manager = new BackupFileManager();

    // Parse and restore the backup
    const backupFile = await manager.parseBackupFile(backupData);

    if (backupFile.encryptionMethod !== 'password') {
      throw new WalletError(
        "Can only register with password-encrypted backups. Use restoreFromBackupFile() for passkey-encrypted backups."
      );
    }

    const { mnemonic, ethereumAddress } = await manager.restoreWithPassword(
      backupFile,
      password
    );

    // Verify the mnemonic produces the expected address
    const { Wallet } = await import("ethers");
    const wallet = Wallet.fromPhrase(mnemonic);

    if (wallet.address.toLowerCase() !== ethereumAddress.toLowerCase()) {
      throw new WalletError("Backup verification failed: address mismatch");
    }

    // Set the current wallet
    this.currentWallet = {
      address: ethereumAddress,
      mnemonic,
    };

    // Now register with the restored wallet
    return this.register({ username });
  }

  /**
   * Get cross-device sync status
   */
  async getSyncStatus(): Promise<any> {
    const { DeviceSyncManager } = await import("../sync/backup-sync");
    const syncManager = new DeviceSyncManager();

    return syncManager.getSyncInfo();
  }

  /**
   * Export wallet for syncing to another device
   * Uses passkey encryption so it works on devices where the passkey is synced
   */
  async exportForSync(): Promise<{ blob: Blob; filename: string; qrCode?: string }> {
    if (!this.currentUser) {
      throw new WalletError("Must be authenticated to export for sync");
    }

    const mnemonic = await this.getMnemonicFromSession(true);

    const walletData = await this.walletStorage.retrieve(
      this.currentUser.ethereumAddress
    );
    if (!walletData) {
      throw new WalletError("No wallet data found");
    }

    const storage = new (await import("../auth/storage")).CredentialStorage();
    const credential = await storage.getCredentialById(walletData.credentialId);
    if (!credential) {
      throw new WalletError("Credential not found");
    }

    const { DeviceSyncManager } = await import("../sync/backup-sync");
    const syncManager = new DeviceSyncManager();

    const { backupFile, blob } = await syncManager.exportForSync(
      mnemonic,
      this.currentUser.ethereumAddress,
      credential.id,
      credential.publicKey
    );

    const filename = `w3pk-sync-${this.currentUser.ethereumAddress.substring(0, 8)}.json`;

    // Optionally generate QR code
    let qrCode: string | undefined;
    try {
      qrCode = await syncManager.generateSyncQR(backupFile);
    } catch (error) {
      // QR code generation is optional
      console.warn('QR code generation failed:', error);
    }

    return { blob, filename, qrCode };
  }

  /**
   * Import wallet from another device (sync wallet to this device)
   * Use case: User has passkey on both devices, wallet only on one
   */
  async importFromSync(
    syncData: string | Blob
  ): Promise<{ ethereumAddress: string; success: boolean }> {
    if (!this.currentUser) {
      throw new WalletError(
        "Must be logged in to import from sync. Call login() first."
      );
    }

    const { DeviceSyncManager } = await import("../sync/backup-sync");
    const { BackupFileManager } = await import("../backup/backup-file");

    const fileManager = new BackupFileManager();
    const syncManager = new DeviceSyncManager();

    const backupFile = await fileManager.parseBackupFile(syncData);

    // Get current credential
    const walletData = await this.walletStorage.retrieve(
      this.currentUser.ethereumAddress
    );
    if (!walletData) {
      throw new WalletError("No wallet data found for current user");
    }

    const storage = new (await import("../auth/storage")).CredentialStorage();
    const credential = await storage.getCredentialById(walletData.credentialId);
    if (!credential) {
      throw new WalletError("Credential not found");
    }

    // Import and decrypt
    const { mnemonic, ethereumAddress } = await syncManager.importFromSync(
      backupFile,
      credential.id,
      credential.publicKey
    );

    // Store the wallet with current credential
    const encryptionKey = await (await import("../wallet/crypto")).deriveEncryptionKeyFromWebAuthn(
      credential.id,
      credential.publicKey
    );

    const encryptedMnemonic = await (await import("../wallet/crypto")).encryptData(
      mnemonic,
      encryptionKey
    );

    await this.walletStorage.store({
      ethereumAddress,
      encryptedMnemonic,
      credentialId: credential.id,
      createdAt: new Date().toISOString(),
    });

    return {
      ethereumAddress,
      success: true,
    };
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
   * Also clears ALL persistent sessions from IndexedDB
   */
  async clearSession(): Promise<void> {
    await this.sessionManager.clearSession();
  }

  /**
   * Update session duration
   * @param hours - Duration in hours
   */
  setSessionDuration(hours: number): void {
    this.sessionManager.setSessionDuration(hours);
  }
}
