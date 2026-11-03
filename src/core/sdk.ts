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
import { LocalStorageWalletStorage } from "../wallet/storage";
import {
  createWalletFromMnemonic,
  generateBIP39Wallet,
} from "../wallet/generate";
import {
  getOriginSpecificAddress,
  getCurrentOrigin,
  normalizeOrigin,
  DEFAULT_TAG,
  DEFAULT_MODE,
} from "../wallet/origin-derivation";
import {
  derivePrfSessionKey,
  deriveWalletKey,
  encryptData,
  decryptData,
  PRF_INPUT,
} from "../wallet/crypto";
import { StealthAddressModule } from "../stealth";
import { SessionManager } from "./session";
import { CredentialStorage } from "../auth/storage";
import {
  assertPrfSecretTag,
  derivePrfSecret,
  evaluatePrf,
  PRF_SECRET_LABEL,
  type PrfSecret,
} from "../auth/prf";
import type { SemaphoreIdentity } from "../zk/semaphore";
import type { ZKProofModule } from "../zk/index";
import type {
  ZkInputs,
  ZkProveArtifacts,
  ZkProveOptions,
  ZkProveResult,
} from "../zk/prove";
// ZK module imported dynamically to avoid bundling dependencies
import type { Web3PasskeyConfig, InternalConfig } from "./config";
import type { BackupStatus } from "../backup/types";
import { detectEvictionRisk } from "../utils/eviction";
import { DEFAULT_CONFIG } from "./config";
import type { UserInfo, GeneratedWallet, DerivedWallet, RegisterResult, SecurityMode, SigningMethod, SignMessageOptions } from "../types";
import {
  AuthenticationError,
  CryptoError,
  PrfUnsupportedError,
  WalletError,
  WalletMissingError,
} from "./errors";
import { getEndpoints } from "../chainlist";
import type { EncryptedPayload } from "../crypto/mlkem";
import type { DeviceSyncInfo } from "../sync/backup-sync";
import type { SyncCapabilities } from "../sync/types";
import { supportsEIP7702 } from "../eip7702";
import type { GuardianShare } from "../recovery/backup-based-recovery";
import { createEIP1193Provider, type EIP1193ProviderInterface } from "./eip1193";
import type { SdkContext } from "./context";
import { deriveMLKemPublicKey, mlkemDecrypt, mlkemEncrypt } from "./mlkem";
import {
  generateGuardianInvite,
  recoverFromGuardians,
  setupSocialRecovery,
} from "./social-recovery";
import {
  bootstrapCredential,
  confirmRecoveryPhraseBackup,
  createBackupFile,
  detectSyncCapabilities,
  exportForSync,
  getBackupStatus,
  getSyncStatus,
  importFromSync,
  registerWithBackupFile,
  restoreFromBackupFile,
  syncWalletWithPasskey,
} from "./backup-sync";

/**
 * ZKProofModule members as exposed by `Web3Passkey.zk`: methods return a
 * Promise, properties become calls resolving to their value
 */
export type ZKMethods = {
  [K in keyof ZKProofModule]: ZKProofModule[K] extends (...args: infer A) => infer R
    ? (...args: A) => Promise<Awaited<R>>
    : () => Promise<ZKProofModule[K]>;
};

export class Web3Passkey {
  private config: InternalConfig;
  private walletStorage: LocalStorageWalletStorage;
  private currentUser: UserInfo | null = null;
  private currentWallet: GeneratedWallet | null = null;
  private persisted: boolean | null = null;
  private sessionManager: SessionManager;

  public stealth?: StealthAddressModule;
  private zkModule?: ZKProofModule;
  private readonly ctx: SdkContext = this.createContext();

  constructor(config: Web3PasskeyConfig = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config } as InternalConfig;
    this.walletStorage = new LocalStorageWalletStorage();

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

  /** The internals the feature modules work on, read when they run */
  private createContext(): SdkContext {
    const sdk = this;
    return {
      get currentUser() {
        return sdk.currentUser;
      },
      set currentUser(user) {
        sdk.currentUser = user;
      },
      get currentWallet() {
        return sdk.currentWallet;
      },
      set currentWallet(wallet) {
        sdk.currentWallet = wallet;
      },
      get config() {
        return sdk.config;
      },
      get walletStorage() {
        return sdk.walletStorage;
      },
      get sessionManager() {
        return sdk.sessionManager;
      },
      getMnemonicFromSession: (forceAuth, securityMode) =>
        sdk.getMnemonicFromSession(forceAuth, securityMode),
      storeWallet: (...args) => sdk.storeWallet(...args),
      requestPersistentStorage: () => sdk.requestPersistentStorage(),
      register: (options) => sdk.register(options),
    };
  }

  /**
   * Lazy-load ZK module to prevent bundling unless accessed
   */
  private async loadZKModule(): Promise<ZKProofModule> {
    if (this.zkModule) {
      return this.zkModule;
    }

    try {
      const { ZKProofModule } = await import("w3pk/zk");
      const zkConfig = this.config.zkProofs || {};
      this.zkModule = new ZKProofModule(zkConfig);
      return this.zkModule;
    } catch (error) {
      throw new Error(
        "ZK module not available. Install the optional dependencies snarkjs and circomlibjs"
      );
    }
  }

  /**
   * Retrieve mnemonic from active session or trigger authentication
   * @param forceAuth - Bypass session cache and require fresh authentication
   * @param securityMode - Security mode to use for session persistence (default: STANDARD)
   */
  private async getMnemonicFromSession(
    forceAuth: boolean = false,
    securityMode: SecurityMode = 'STANDARD'
  ): Promise<string> {
    const effectiveMode = securityMode;

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

    const authResult = await login(this.config.userVerification);
    if (!authResult.user) {
      throw new WalletError("Authentication failed");
    }
    if (!authResult.prfOutput) {
      throw new PrfUnsupportedError(authResult.user.credentialId);
    }

    const mnemonic = await decryptData(
      walletData.encryptedMnemonic,
      await deriveWalletKey(authResult.prfOutput)
    );

    // This assertion's PRF output (re-)keys the persistent session
    const prfSessionKey = authResult.prfOutput
      ? await derivePrfSessionKey(
          authResult.prfOutput,
          this.sessionManager.storesSessionKey
        )
      : undefined;

    await this.sessionManager.startSession(
      mnemonic,
      walletData.credentialId,
      this.currentUser.ethereumAddress,
      prfSessionKey,
      effectiveMode
    );

    return mnemonic;
  }

  /**
   * Store the wallet encrypted under the key derived from `prfOutput`,
   * the PRF output at `PRF_INPUT` of the wallet's passkey
   */
  private async storeWallet(
    ethereumAddress: string,
    mnemonic: string,
    credentialId: string,
    prfOutput: BufferSource,
    createdAt = new Date().toISOString()
  ): Promise<void> {
    await this.walletStorage.store({
      ethereumAddress,
      encryptedMnemonic: await encryptData(mnemonic, await deriveWalletKey(prfOutput)),
      credentialId,
      createdAt,
    });
  }

  /**
   * Register new user with WebAuthn
   * Automatically generates wallet if none exists and associates with passkey
   */
  async register(options: { username: string }): Promise<RegisterResult> {
    try {
      if (!this.currentWallet?.address) {
        await this.generateWallet();
      }

      const ethereumAddress = this.currentWallet!.address;
      const mnemonic = this.currentWallet!.mnemonic!;

      const registration = await register({
        username: options.username,
        ethereumAddress,
        userVerification: this.config.userVerification,
      });

      const storage = new CredentialStorage();
      const credential = await storage.getCredentialByAddress(ethereumAddress);

      this.currentUser = {
        username: options.username,
        ethereumAddress,
        credentialId: credential?.id || '',
      };

      if (!credential) {
        throw new WalletError("Credential not found after registration");
      }

      const credentialId = credential.id;

      // Some platforms evaluate the PRF at creation; if this one didn't,
      // one assertion does. Without PRF, the wallet stays in memory only.
      let prfOutput = registration.prfOutput;
      if (!prfOutput) {
        try {
          prfOutput = (await evaluatePrf(PRF_INPUT, credentialId)).output;
        } catch (error) {
          if (!(error instanceof PrfUnsupportedError)) throw error;
        }
      }

      if (prfOutput) {
        await this.storeWallet(ethereumAddress, mnemonic, credentialId, prfOutput);
      }

      const prfSessionKey = prfOutput
        ? await derivePrfSessionKey(
            prfOutput,
            this.sessionManager.storesSessionKey
          )
        : undefined;

      await this.sessionManager.startSession(
        mnemonic,
        credentialId,
        ethereumAddress,
        prfSessionKey,
        'STANDARD' // Default security mode for register
      );

      this.currentWallet = {
        address: ethereumAddress,
        mnemonic,
      };

      const { BackupManager } = await import("../backup/manager");
      const hasBackup = await new BackupManager().hasBackup(ethereumAddress);
      const evictionRisk = await detectEvictionRisk();

      void this.requestPersistentStorage();
      this.config.onAuthStateChanged?.(true, this.currentUser);

      return {
        address: ethereumAddress,
        username: options.username,
        hasBackup,
        evictionRisk,
      };
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
        const storage = new CredentialStorage();
        const credential = await storage.getCredentialById(silentRestore.credentialId);

        // Verify wallet exists
        const walletData = await this.walletStorage.retrieve(
          silentRestore.ethereumAddress
        );

        if (!walletData) {
          // Wallet was deleted but session still exists - clear session and retry with auth
          // A failed persistent clear shouldn't abort the retry; login() will re-authenticate
          await this.sessionManager.clearSession().catch((error) =>
            console.warn('[w3pk] Failed to clear stale session:', error)
          );
          return this.login(); // Retry with authentication
        }

        this.currentUser = {
          username: credential?.username || silentRestore.ethereumAddress,
          ethereumAddress: silentRestore.ethereumAddress,
          credentialId: silentRestore.credentialId,
        };

        void this.requestPersistentStorage();
        this.config.onAuthStateChanged?.(true, this.currentUser);
        return this.currentUser;
      }

      // STEP 2: No silent restore - proceed with WebAuthn authentication
      const result = await login(this.config.userVerification);

      if (!result.verified || !result.user) {
        throw new AuthenticationError("Login failed");
      }

      const walletData = await this.walletStorage.retrieve(
        result.user.ethereumAddress
      );

      if (!walletData) {
        throw new WalletMissingError(
          result.user.credentialId,
          result.user.ethereumAddress
        );
      }

      this.currentUser = {
        username: result.user.username,
        ethereumAddress: result.user.ethereumAddress,
        credentialId: result.user.credentialId,
      };

      // Key derived from THIS assertion's PRF output: decrypts the existing
      // persistent session (deterministic PRF input → same key as when the
      // blob was written) and re-keys the next one
      const prfSessionKey = result.prfOutput
        ? await derivePrfSessionKey(
            result.prfOutput,
            this.sessionManager.storesSessionKey
          )
        : undefined;

      // Try to restore from persistent session first (if requireReauth is true)
      const restoredMnemonic = await this.sessionManager.restoreFromPersistentStorage(
        this.currentUser.ethereumAddress,
        walletData.credentialId,
        prfSessionKey
      );

      if (restoredMnemonic) {
        // A record stored under the old key can't be decrypted with the
        // wallet key: re-encrypt it from the session's mnemonic
        if (result.prfOutput) {
          const walletKey = await deriveWalletKey(result.prfOutput);
          const current = await decryptData(walletData.encryptedMnemonic, walletKey)
            .then(() => true, () => false);
          if (!current) {
            await this.storeWallet(
              walletData.ethereumAddress,
              restoredMnemonic,
              walletData.credentialId,
              result.prfOutput,
              walletData.createdAt
            );
          }
        }
      } else {
        // Without PRF, or under the old key, the wallet can't be decrypted
        // here: it has to be restored from a backup
        const walletMissing = () => {
          this.currentUser = null;
          return new WalletMissingError(
            result.user!.credentialId,
            result.user!.ethereumAddress
          );
        };
        if (!result.prfOutput) {
          throw walletMissing();
        }

        let mnemonic: string;
        try {
          mnemonic = await decryptData(
            walletData.encryptedMnemonic,
            await deriveWalletKey(result.prfOutput)
          );
        } catch (error) {
          if (!(error instanceof CryptoError)) throw error;
          throw walletMissing();
        }

        // Start new session with persistence
        await this.sessionManager.startSession(
          mnemonic,
          walletData.credentialId,
          this.currentUser.ethereumAddress,
          prfSessionKey,
          'STANDARD' // Default security mode
        );
      }

      void this.requestPersistentStorage();
      this.config.onAuthStateChanged?.(true, this.currentUser);

      return this.currentUser;
    } catch (error) {
      this.config.onError?.(error as any);
      throw error;
    }
  }

  /**
   * Logout current user and clear session
   *
   * The user is always logged out in memory, even if clearing persistent
   * storage fails — in that case a StorageError is thrown so the app knows
   * a persistent session may still exist on the device
   *
   * @throws {StorageError} if persistent sessions could not be cleared
   */
  async logout(): Promise<void> {
    this.currentUser = null;
    this.currentWallet = null;
    try {
      await this.sessionManager.clearSession();
    } finally {
      this.config.onAuthStateChanged?.(false, undefined);
    }
  }

  get isAuthenticated(): boolean {
    return this.currentUser !== null;
  }

  get user(): UserInfo | null {
    return this.currentUser;
  }

  /**
   * Whether the browser granted persistent storage (`navigator.storage.persist()`),
   * requested after each register, login and restore: true means the origin's
   * storage is exempt from storage-pressure eviction. null until the browser
   * answers (Firefox asks the user), or where the API is missing.
   */
  get storagePersisted(): boolean | null {
    return this.persisted;
  }

  private async requestPersistentStorage(): Promise<void> {
    if (typeof navigator === "undefined" || !navigator.storage?.persist) return;
    try {
      this.persisted = await navigator.storage.persist();
    } catch {
      this.persisted = false;
    }
  }

  /**
   * List existing credentials (usernames and addresses)
   * Useful for allowing users to select which wallet to login to
   *
   * @returns array of credentials with username, address, and metadata
   * @example
   * const wallets = await w3pk.listExistingCredentials()
   * if (wallets.length > 0) {
   *   console.warn(`You have ${wallets.length} wallet(s) on this device`)
   *   wallets.forEach(w => {
   *     console.log(`${w.username}: ${w.ethereumAddress}`)
   *   })
   * }
   */
  async listExistingCredentials(): Promise<Array<{
    username: string;
    ethereumAddress: string;
    createdAt: string;
    lastUsed: string;
  }>> {
    try {
      const storage = new CredentialStorage();
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
   * @internal - Called automatically by register()
   */
  private async generateWallet(): Promise<GeneratedWallet> {
    try {
      const wallet = generateBIP39Wallet();

      this.currentWallet = {
        address: wallet.address,
        mnemonic: wallet.mnemonic,
      };

      return {
        address: wallet.address,
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
    options?: { requireAuth?: boolean }
  ): Promise<DerivedWallet> {
    try {
      if (!this.currentUser) {
        throw new WalletError("Must be authenticated to derive wallet");
      }

      const effectiveMode = mode || DEFAULT_MODE;
      const effectiveTag = tag || DEFAULT_TAG;
      const origin = getCurrentOrigin();

      // PRIMARY mode: Use WebAuthn P-256 public key directly (EIP-7951)
      if (effectiveMode === 'PRIMARY') {
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
   * SECURITY: This method ensures no private key is ever returned to the application,
   * even in YOLO mode. It directly derives the address without creating a wallet object
   * that might contain sensitive key material.
   *
   * @param mode - Security mode (default: "STANDARD")
   * @param tag - Derivation tag (default: "MAIN")
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
    tag?: string
  ): Promise<string> {
    try {
      if (!this.currentUser) {
        throw new WalletError("Must be authenticated to get address");
      }

      const effectiveMode = mode || DEFAULT_MODE;
      const effectiveTag = tag || DEFAULT_TAG;
      const origin = getCurrentOrigin();

      // PRIMARY mode: Use WebAuthn P-256 public key directly (EIP-7951)
      if (effectiveMode === 'PRIMARY') {
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
   * Import a mnemonic phrase as the logged-in passkey's wallet, replacing
   * the stored one. The imported wallet is stored under its own address
   * before the credential points at it, and the previous wallet is deleted
   * only after.
   *
   * @throws WalletError if not logged in, or the phrase isn't a valid BIP39 mnemonic
   * @throws AuthenticationError if the passkey prompt is cancelled, and PrfUnsupportedError if the authenticator returns no PRF output (nothing stored changes)
   */
  async importMnemonic(mnemonic: string): Promise<void> {
    try {
      if (!this.currentUser) {
        throw new WalletError("Must be authenticated to import mnemonic");
      }

      const phrase = (mnemonic ?? "").trim().split(/\s+/).join(" ");
      const ethereumAddress = createWalletFromMnemonic(phrase).address;

      const authResult = await login(this.config.userVerification);
      if (authResult.user?.credentialId !== this.currentUser.credentialId) {
        throw new WalletError("Authenticate with the logged-in passkey to import a mnemonic");
      }
      if (!authResult.prfOutput) {
        throw new PrfUnsupportedError(this.currentUser.credentialId);
      }
      const prfOutput = authResult.prfOutput;

      const credential = await new CredentialStorage().getCredentialById(
        this.currentUser.credentialId
      );
      if (!credential) {
        throw new WalletError("Credential not found");
      }

      await bootstrapCredential(this.ctx, credential, phrase, ethereumAddress, prfOutput, true);

      this.currentWallet = { address: ethereumAddress, mnemonic: phrase };
    } catch (error) {
      this.config.onError?.(error as any);
      throw error;
    }
  }

  /**
   * Sign message with wallet
   *
   * By default, signs with STANDARD mode + MAIN tag (origin-centric address).
   * You can specify a different mode and tag to sign from a specific derived address.
   *
   * @param message - Message to sign; bytes are signed as-is, and only with EIP191
   * @param options.mode - Security mode for derivation (default: "STANDARD")
   * @param options.tag - Tag for derivation (default: "MAIN")
   * @param options.requireAuth - Force fresh authentication
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
    message: string | Uint8Array,
    options?: SignMessageOptions
  ): Promise<{
    signature: string;
    address: string;
    mode: SecurityMode;
    tag: string;
    origin: string;
  }> {
    try {
      const effectiveMode = options?.mode || DEFAULT_MODE;
      const signingMethod = options?.signingMethod || 'EIP191';

      if (typeof message !== 'string' && signingMethod !== 'EIP191') {
        throw new WalletError(`${signingMethod} signing requires a string message`);
      }

      // PRIMARY addresses come from the passkey's P-256 key, which cannot produce
      // an EIP-191 signature that recovers to them
      if (effectiveMode === 'PRIMARY' && signingMethod === 'SIWE') {
        throw new WalletError(
          "SIWE signing is not supported in PRIMARY mode. Use STANDARD, STRICT or YOLO mode."
        );
      }

      if (!this.currentUser) {
        throw new WalletError("Must be authenticated to sign message");
      }

      const effectiveTag = options?.tag || DEFAULT_TAG;
      const origin = getCurrentOrigin();

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
        case 'SIWE':
          // EIP-191 compliant message signing
          // SIWE (EIP-4361) messages are also signed with EIP-191 for EOA accounts
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
          let hashToSign = message as string;
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
        userVerification: this.config.userVerification,
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
   * Send a transaction using the derived wallet for the current security mode
   *
   * @param tx - Transaction parameters
   * @param tx.to - Recipient address
   * @param tx.value - Value in wei (optional)
   * @param tx.data - Hex calldata (optional, default "0x")
   * @param tx.chainId - Chain ID (required)
   * @param tx.gasLimit - Gas limit override (optional)
   * @param tx.maxFeePerGas - EIP-1559 max fee per gas (optional)
   * @param tx.maxPriorityFeePerGas - EIP-1559 max priority fee per gas (optional)
   * @param tx.nonce - Nonce override (optional)
   * @param options.mode - Security mode (default: STANDARD)
   * @param options.tag - Wallet tag (optional)
   * @param options.requireAuth - Force fresh authentication (optional)
   * @param options.rpcUrl - RPC endpoint override (optional, required for PRIMARY mode);
   *   without it, the first `rpcUrls` endpoint set for the chain is used, then the
   *   first HTTPS chainid.network endpoint
   * @returns Transaction hash and metadata
   *
   * @example
   * const result = await w3pk.sendTransaction({ to: "0x...", value: 1000000000000000000n, chainId: 1 })
   * console.log(result.hash)
   */
  async sendTransaction(
    tx: {
      to: string;
      value?: bigint;
      data?: string;
      chainId: number;
      gasLimit?: bigint;
      maxFeePerGas?: bigint;
      maxPriorityFeePerGas?: bigint;
      nonce?: number;
    },
    options?: {
      mode?: SecurityMode;
      tag?: string;
      requireAuth?: boolean;
      rpcUrl?: string;
    }
  ): Promise<{
    hash: string;
    from: string;
    chainId: number;
    mode: SecurityMode;
    tag: string;
    origin: string;
  }> {
    try {
      if (!this.currentUser) {
        throw new WalletError("Must be authenticated to send transaction");
      }

      const effectiveMode = options?.mode || DEFAULT_MODE;
      const effectiveTag = options?.tag || DEFAULT_TAG;
      const origin = getCurrentOrigin();

      // PRIMARY mode requires a bundler/relayer rpcUrl
      if (effectiveMode === 'PRIMARY') {
        if (!options?.rpcUrl) {
          throw new WalletError(
            "PRIMARY mode requires options.rpcUrl pointing to a bundler or sponsoring relayer. " +
            "The P-256 address cannot pay gas directly without a deployed P-256-verifier contract via EIP-7702."
          );
        }
        throw new WalletError(
          "PRIMARY mode sendTransaction is not yet supported. " +
          "Use signMessageWithPasskey() to obtain a P-256 signature and submit via a bundler manually."
        );
      }

      // STRICT mode: always require authentication (no persistent sessions)
      const requireAuth = effectiveMode === 'STRICT' ? true : (options?.requireAuth || false);

      const mnemonic = await this.getMnemonicFromSession(requireAuth, effectiveMode);

      // Derive the wallet from the specified mode and tag
      const derived = await getOriginSpecificAddress(mnemonic, origin, effectiveMode, effectiveTag);

      const { Wallet, JsonRpcProvider } = await import("ethers");

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

      // Resolve RPC endpoint
      const rpcUrl = options?.rpcUrl
        ?? this.config.rpcUrls?.[tx.chainId]?.[0]
        ?? (await getEndpoints(tx.chainId))[0];
      if (!rpcUrl) {
        throw new WalletError(
          `No RPC endpoint found for chainId ${tx.chainId}. Set rpcUrls in the config or pass options.rpcUrl.`
        );
      }

      const provider = new JsonRpcProvider(rpcUrl);
      const connected = wallet.connect(provider);

      const response = await connected.sendTransaction({
        to: tx.to,
        value: tx.value,
        data: tx.data ?? "0x",
        chainId: tx.chainId,
        gasLimit: tx.gasLimit,
        maxFeePerGas: tx.maxFeePerGas,
        maxPriorityFeePerGas: tx.maxPriorityFeePerGas,
        nonce: tx.nonce,
      });

      return {
        hash: response.hash,
        from: derived.address,
        chainId: tx.chainId,
        mode: derived.mode,
        tag: derived.tag,
        origin: derived.origin,
      };
    } catch (error) {
      this.config.onError?.(error as any);
      throw new WalletError("Failed to send transaction", error);
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
   * @param options.mode - Security mode of the signing wallet (default: STANDARD, PRIMARY is refused)
   * @param options.tag - Wallet tag (default: MAIN)
   *
   * Without `params.privateKey`, signs with the origin-specific derived key
   * (never the master key) after a fresh user-verified passkey assertion.
   */
  async signAuthorization(
    params: {
      contractAddress: string;
      chainId?: number;
      nonce?: bigint;
      privateKey?: string;
    },
    options?: { mode?: SecurityMode; tag?: string }
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

      const { Wallet, Signature } = await import("ethers");
      const { hashEIP7702AuthorizationMessage, verifyEIP7702Authorization } = await import("../eip7702/utils");

      let wallet: any;

      if (params.privateKey) {
        wallet = new Wallet(params.privateKey);
      } else {
        const effectiveMode = options?.mode || DEFAULT_MODE;
        const effectiveTag = options?.tag || DEFAULT_TAG;

        if (effectiveMode === 'PRIMARY') {
          throw new WalletError(
            "PRIMARY mode cannot sign EIP-7702 authorizations: its P-256 passkey address has no secp256k1 key. " +
            "Use STANDARD, STRICT or YOLO mode."
          );
        }

        const origin = getCurrentOrigin();
        const mnemonic = await this.getMnemonicFromSession(true, effectiveMode);
        const derived = await getOriginSpecificAddress(mnemonic, origin, effectiveMode, effectiveTag);

        if (derived.privateKey) {
          wallet = new Wallet(derived.privateKey);
        } else {
          const { deriveWalletFromMnemonic } = await import("../wallet/generate");
          const { privateKey } = deriveWalletFromMnemonic(mnemonic, derived.index);
          wallet = new Wallet(privateKey);
        }
      }

      const chainId = BigInt(params.chainId || 1);
      const nonce = params.nonce || 0n;

      // Hash EIP-7702 authorization message using shared utility
      const messageHash = hashEIP7702AuthorizationMessage(
        chainId,
        params.contractAddress,
        nonce
      );

      const signature = wallet.signingKey.sign(messageHash);
      const sig = Signature.from(signature);

      // Verify signature before returning
      const authorization = {
        chainId,
        address: params.contractAddress.toLowerCase(),
        nonce,
        yParity: sig.yParity,
        r: sig.r,
        s: sig.s
      };

      const isValid = verifyEIP7702Authorization(
        chainId,
        params.contractAddress,
        nonce,
        authorization,
        wallet.address
      );

      if (!isValid) {
        throw new WalletError("Signature verification failed - this should not happen");
      }

      // Return EIP-7702 authorization object
      // IMPORTANT: address field should be the contract address being delegated to,
      // NOT the signer's ethereum address
      return authorization;
    } catch (error) {
      this.config.onError?.(error as any);
      throw new WalletError("Failed to sign authorization", error);
    }
  }

  /**
   * RPC endpoints for a chain: those set in `rpcUrls` first, then the HTTPS
   * chainid.network endpoints that need no API key
   */
  async getEndpoints(chainId: number): Promise<string[]> {
    const appEndpoints = this.config.rpcUrls?.[chainId] ?? [];
    return [...new Set([...appEndpoints, ...(await getEndpoints(chainId))])];
  }

  async supportsEIP7702(
    chainId: number,
    options?: { maxEndpoints?: number; timeout?: number }
  ): Promise<boolean> {
    return supportsEIP7702(chainId, this.getEndpoints.bind(this), options);
  }

  /**
   * Return an EIP-1193 compatible provider backed by this SDK instance.
   *
   * The returned object implements the standard `request({ method, params })`
   * interface so it can be plugged directly into ethers `BrowserProvider`,
   * viem's `custom` transport, wagmi's `injected` / `custom` connector, or
   * any other EIP-1193 consumer.
   *
   * Supported JSON-RPC methods:
   * - eth_accounts / eth_requestAccounts  → derived STANDARD+MAIN address
   * - eth_chainId                          → from options.chainId (default: 1)
   * - eth_sendTransaction                  → delegates to sendTransaction()
   * - personal_sign / eth_sign            → delegates to signMessage() EIP-191
   * - eth_signTypedData_v4                → delegates to signMessage() EIP-712
   * - wallet_switchEthereumChain          → updates the active chainId
   *
   * @param options.mode     - Security mode for signing/sending (default: 'STANDARD')
   * @param options.tag      - Wallet tag (default: 'MAIN')
   * @param options.chainId  - Initial chainId reported to consumers (default: 1)
   * @param options.rpcUrl   - RPC endpoint override passed to sendTransaction()
   *
   * @example
   * // ethers v6
   * const provider = new BrowserProvider(w3pk.getEIP1193Provider())
   *
   * // viem
   * const client = createWalletClient({ transport: custom(w3pk.getEIP1193Provider()) })
   *
   * // wagmi (custom connector)
   * const connector = injected({ target: () => ({ id: 'w3pk', provider: w3pk.getEIP1193Provider() }) })
   */
  getEIP1193Provider(options?: {
    mode?: SecurityMode;
    tag?: string;
    chainId?: number;
    rpcUrl?: string;
  }): EIP1193ProviderInterface {
    return createEIP1193Provider(this, options);
  }

  /**
   * Lazily loaded ZKProofModule (from `w3pk/zk`): each member loads the
   * module on first call and returns a Promise; a property such as
   * `isAvailable` resolves to its value, and `isAvailable()` resolves to
   * false when the module can't load
   */
  get zk(): ZKMethods {
    return new Proxy({} as ZKMethods, {
      get: (_target, prop) => {
        if (typeof prop === "symbol" || prop === "then") return undefined;
        return async (...args: unknown[]) => {
          const zkModule =
            prop === "isAvailable"
              ? await this.loadZKModule().catch(() => null)
              : await this.loadZKModule();
          if (!zkModule) return false;
          if (!(prop in zkModule) || prop in Object.prototype) {
            throw new TypeError(`w3pk.zk.${prop} is not a function`);
          }
          const member: unknown = zkModule[prop as keyof ZKProofModule];
          return typeof member === "function"
            ? member.apply(zkModule, args)
            : member;
        };
      },
    });
  }

  /**
   * Get backup status
   */
  async getBackupStatus(): Promise<BackupStatus> {
    return getBackupStatus(this.ctx);
  }

  /**
   * Record that the user wrote down their recovery phrase
   * Call it once the user confirms, so getBackupStatus() reports a backup
   */
  async confirmRecoveryPhraseBackup(): Promise<void> {
    return confirmRecoveryPhraseBackup(this.ctx);
  }

  /**
   * Create simplified backup file
   * This backup can be used to:
   * - Restore wallet with existing passkey
   * - Register new passkey with this wallet
   * - Sync wallet across devices
   * - Split among guardians for social recovery
   *
   * Creates a password backup (BackupFile v3, Argon2id): the backup that
   * restores without a passkey. A PRF backup comes from exportForSync().
   *
   * @param password - Encrypts the backup
   * @throws WeakPasswordError when isStrongPassword() refuses the password, with its feedback
   */
  async createBackupFile(password: string): Promise<{ blob: Blob; filename: string }> {
    if (arguments.length > 1) {
      throw new WalletError(
        "createBackupFile() takes only the password: createBackupFile(password)"
      );
    }
    return createBackupFile(this.ctx, password);
  }

  /**
   * Set up social recovery by splitting backup file among guardians
   * Uses Shamir Secret Sharing to split the backup - requires M-of-N guardians to recover
   *
   * @param guardians - List of guardian names/emails
   * @param threshold - Number of guardians required to recover (M-of-N)
   * @param password - Encrypts the backup that the guardians' shares rebuild
   * @throws WeakPasswordError when isStrongPassword() refuses the password, with its feedback
   */
  async setupSocialRecovery(
    guardians: { name: string; email?: string }[],
    threshold: number,
    password: string
  ): Promise<{
    guardianShares: GuardianShare[];
    setupComplete: boolean;
  }> {
    return setupSocialRecovery(this.ctx, guardians, threshold, password);
  }

  /**
   * Generate guardian invitation document and QR code
   *
   * @param guardianShare - The guardian's share data
   * @param message - Optional custom message for the guardian
   */
  async generateGuardianInvite(
    guardianShare: GuardianShare,
    message?: string
  ): Promise<{
    qrCodeDataURL?: string;
    shareDocument: string;
    downloadBlob: Blob;
    filename: string;
  }> {
    return generateGuardianInvite(guardianShare, message);
  }

  /**
   * Recover wallet from guardian shares
   * Combines M-of-N guardian shares to reconstruct the backup file
   *
   * @param shares - Array of guardian share objects (JSON strings or parsed objects)
   * @param password - Password of the backup the shares rebuild
   */
  async recoverFromGuardians(
    shares: Array<string | GuardianShare>,
    password: string
  ): Promise<{ mnemonic: string; ethereumAddress: string }> {
    return recoverFromGuardians(shares, password);
  }

  /**
   * Restore wallet from backup file with existing passkey
   * Use case: User has passkey synced to this device
   *
   * When logged out, a restored password backup stays in memory: log in
   * and call importMnemonic(), or call registerWithBackupFile() to create
   * a new passkey for this wallet.
   *
   * A PRF backup takes one assertion with its passkey, no password, and sets
   * this device up for that passkey (as importFromSync() does).
   *
   * When logged in, the restored wallet replaces the stored one only after
   * the passkey assertion succeeds. A backup of another address than the
   * logged-in one needs `allowAddressChange: true`, which the app sets once
   * the user confirms the replacement.
   *
   * @throws UnsupportedBackupVersionError for a file that isn't BackupFile v3
   * @throws SyncBootstrapError ('CREDENTIAL_MISMATCH') for a PRF backup of another passkey than the logged-in one
   * @throws AddressChangeError for a backup of another address without `allowAddressChange`
   * @throws AuthenticationError if the passkey prompt is cancelled, and PrfUnsupportedError if the authenticator returns no PRF output, when logged in (nothing stored changes)
   */
  async restoreFromBackupFile(
    backupData: string | Blob,
    password?: string,
    options?: { allowAddressChange?: boolean }
  ): Promise<{ mnemonic: string; ethereumAddress: string }> {
    return restoreFromBackupFile(this.ctx, backupData, password, options);
  }

  /**
   * Sync wallet to this device using existing passkey + backup file
   *
   * This method implements the two-step sync flow:
   * 1. Prompts user to select their passkey (from iCloud/Google Password Manager)
   * 2. Uses that passkey + backup file to restore wallet data
   *
   * This allows the user to use the same PRIMARY mode webauthn account on multiple devices.
   *
   * A PRF backup (from exportForSync()) takes a single assertion restricted
   * to its passkey and no password.
   *
   * @param backupData - Backup file (JSON string or Blob) - can be pasted by user
   * @param password - Password to decrypt backup (if password-encrypted)
   * @returns Restored wallet info
   */
  async syncWalletWithPasskey(
    backupData: string | Blob,
    password?: string
  ): Promise<{ mnemonic: string; ethereumAddress: string }> {
    return syncWalletWithPasskey(this.ctx, backupData, password);
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
    return registerWithBackupFile(this.ctx, backupData, password, username);
  }

  /**
   * Get cross-device sync status
   */
  async getSyncStatus(): Promise<DeviceSyncInfo | null> {
    return getSyncStatus();
  }

  /**
   * Export wallet for syncing to another device
   *
   * Prompts for the passkey and encrypts with a key derived from its WebAuthn
   * PRF output (`encryptionMethod: 'prf'`): a device where the passkey synced
   * restores it with one prompt and no password. Where the authenticator has
   * no PRF support, `password` makes it fall back to a password backup.
   *
   * @param password - Fallback password when PRF is unavailable
   * @throws PrfUnsupportedError when PRF is unavailable and no password is given
   * @throws WeakPasswordError when isStrongPassword() refuses the password, with its feedback
   */
  async exportForSync(
    password?: string
  ): Promise<{ blob: Blob; filename: string; qrCode?: string }> {
    return exportForSync(this.ctx, password);
  }

  /**
   * Import wallet from another device (sync wallet to this device)
   *
   * Takes a PRF backup from exportForSync(): one assertion restricted to
   * the backup's passkey decrypts it, with no password, on any device where
   * the passkey synced, including one with no data for it. Works without a
   * login. For a password backup (exportForSync()'s fallback), use
   * syncWalletWithPasskey().
   *
   * @throws SyncBootstrapError ('CREDENTIAL_MISMATCH') when logged in with another passkey
   */
  async importFromSync(
    syncData: string | Blob
  ): Promise<{ ethereumAddress: string; success: boolean }> {
    return importFromSync(this.ctx, syncData);
  }

  /**
   * Detect platform sync capabilities
   */
  async detectSyncCapabilities(): Promise<SyncCapabilities> {
    return detectSyncCapabilities();
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
   * Also clears ALL persistent sessions from localStorage
   *
   * @throws {StorageError} if persistent sessions could not be cleared
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

  /**
   * Update the persistent-session duration (the "Remember Me" window).
   * Takes effect the next time a session is persisted — i.e. at the next
   * real (prompted) login, which is also when the blob is re-keyed with a
   * fresh PRF-derived key. The duration is therefore the renewal interval.
   * @param hours - Duration in hours
   */
  setPersistentSessionDuration(hours: number): void {
    this.sessionManager.setPersistentSessionDuration(hours);
  }

  /**
   * Derive a 32-byte secret bound to the passkey, separate per origin and tag
   *
   * Evaluates the WebAuthn PRF extension on a fresh user-verified assertion
   * and runs HKDF-SHA256 on the output. The secret is never derived from or
   * stored with the mnemonic, so it never appears in backups, recovery
   * phrases, sessions or storage. When logged in, the assertion is
   * restricted to the current user's passkey.
   *
   * @param tag - Non-empty label without ':', e.g. "zk-identity"
   * @returns The secret and the credential it is bound to
   * @throws PrfUnsupportedError when the authenticator doesn't support PRF
   *
   * @example
   * const { secret, credentialId } = await w3pk.derivePrfSecret("zk-identity")
   */
  async derivePrfSecret(tag: string): Promise<PrfSecret> {
    try {
      return await derivePrfSecret(
        PRF_SECRET_LABEL,
        normalizeOrigin(getCurrentOrigin()),
        tag,
        this.currentUser?.credentialId
      );
    } catch (error) {
      this.config.onError?.(error as any);
      throw error;
    }
  }

  /**
   * Get the commitment of a Semaphore v4 identity bound to the passkey
   *
   * The identity's private key is a PRF secret for the current origin and
   * `tag`, derived under its own label so `derivePrfSecret(tag)` can't
   * return it. The private key is never returned or stored. A new
   * credential gives a new commitment: keep `credentialId` with the
   * commitment you add to a group, and replace the member when it changes.
   *
   * Requires the optional dependency `@semaphore-protocol/identity`.
   *
   * @param tag - Non-empty label without ':', e.g. "voting"
   * @returns The identity commitment and the credential it is bound to
   * @throws PrfUnsupportedError when the authenticator doesn't support PRF
   * @throws CryptoError when `@semaphore-protocol/identity` isn't installed
   *   (before any prompt) or the tag is invalid
   *
   * @example
   * const { commitment, credentialId } = await w3pk.getSemaphoreIdentity("voting")
   * group.addMember(commitment)
   */
  async getSemaphoreIdentity(tag: string): Promise<SemaphoreIdentity> {
    try {
      const { SEMAPHORE_PRF_LABEL, loadSemaphoreCommitment } = await import("../zk/semaphore");
      const commit = await loadSemaphoreCommitment();
      const { secret, credentialId } = await derivePrfSecret(
        SEMAPHORE_PRF_LABEL,
        normalizeOrigin(getCurrentOrigin()),
        tag,
        this.currentUser?.credentialId
      );
      return { commitment: commit(secret), credentialId };
    } catch (error) {
      this.config.onError?.(error as any);
      throw error;
    }
  }

  /**
   * Prove with a secret bound to the passkey that the app never sees
   *
   * w3pk derives the secret for the current origin and `tag` (by default
   * under its own `w3pk-zk-v1` label, or the Semaphore identity's
   * `secretScalar`), places it in the witness with any inputs `options`
   * declares as derived (Poseidon over the secret and other inputs) or
   * random (fresh, discarded after the call), checks the artifacts against
   * their pins, and runs snarkjs in a Web Worker (in-thread where `Worker`
   * doesn't exist, as in Node, or the worker can't start). Only the proof
   * and public signals come back;
   * a proof whose public signals contain the secret or a random input is
   * refused. Everything checkable without the passkey is checked before
   * the prompt.
   *
   * w3pk runs in the app's JavaScript context: this keeps the secret out
   * of the API, not out of reach of malicious code on the same page.
   *
   * Requires the optional dependencies `snarkjs`, `poseidon-lite` (for
   * derivations) and `@semaphore-protocol/identity` (for `"semaphore"`).
   *
   * @param tag - Non-empty label without ':', e.g. "voting"
   * @param artifacts - The circuit's `.wasm` and `.zkey` (bytes or URLs) and their pinned CIDs
   * @param publicInputs - The circuit's public inputs
   * @param extraWitness - Other private inputs the app provides
   * @param options - Secret source, its input name, derived and random inputs
   * @throws ZkArtifactMismatchError when an artifact doesn't match its pin
   * @throws PrfUnsupportedError when the authenticator doesn't support PRF
   * @throws CryptoError on invalid inputs, missing dependencies or a failed proof
   *
   * @example
   * const { proof, publicSignals } = await w3pk.zkProve(
   *   "voting",
   *   { wasm: wasmUrl, zkey: zkeyUrl, pins },
   *   { proposalId, root },
   *   { vote: 1 },
   *   { secret: "semaphore", derive: { voteSecret: ["secret", "proposalId", 1n] }, random: ["r"] }
   * )
   */
  async zkProve(
    tag: string,
    artifacts: ZkProveArtifacts,
    publicInputs: ZkInputs,
    extraWitness: ZkInputs = {},
    options: ZkProveOptions = {}
  ): Promise<ZkProveResult> {
    try {
      assertPrfSecretTag(tag);
      const { zkProve } = await import("../zk/prove");
      const origin = normalizeOrigin(getCurrentOrigin());
      const credentialId = this.currentUser?.credentialId;
      return await zkProve(
        async (label) => (await derivePrfSecret(label, origin, tag, credentialId)).secret,
        artifacts,
        publicInputs,
        extraWitness,
        options
      );
    } catch (error) {
      this.config.onError?.(error as any);
      throw error;
    }
  }

  /**
   * Derive the hybrid ML-KEM-1024 + X25519 public key from the current wallet
   *
   * Returns the public key that can be shared with others for encryption.
   * The hybrid keypair is derived deterministically from the wallet's private key.
   *
   * @param options - Optional configuration
   * @param options.context - Context string for domain separation (default: MLKEM_DEFAULT_CONTEXT)
   * @param options.mode - Security mode (default: 'YOLO' to access private key)
   * @param options.tag - Tag for address derivation (default: 'MAIN')
   * @param options.requireAuth - Force WebAuthn re-authentication
   * @returns Base64-encoded hybrid public key (1600 bytes: ML-KEM-1024 || X25519)
   *
   * @example
   * ```typescript
   * const w3pk = createWeb3Passkey();
   * await w3pk.login();
   *
   * const publicKey = await w3pk.deriveMLKemPublicKey();
   * // Share publicKey with others so they can encrypt data for you
   * ```
   */
  async deriveMLKemPublicKey(options?: {
    context?: string;
    mode?: SecurityMode;
    tag?: string;
    requireAuth?: boolean;
  }): Promise<string> {
    return deriveMLKemPublicKey(this.ctx, options);
  }

  /**
   * Encrypt data with the hybrid ML-KEM-1024 + X25519 KEM (payload v3) for self + additional recipients
   *
   * Encrypts data such that you (the sender) and specified recipients can decrypt.
   * Your hybrid keypair is derived from your wallet, so you can always decrypt later.
   *
   * @param plaintext - The data to encrypt
   * @param recipientPublicKeys - Array of recipient hybrid public keys (base64 strings or Uint8Arrays, 1600 bytes)
   * @param options - Optional configuration
   * @param options.context - Context string for key derivation (default: MLKEM_DEFAULT_CONTEXT)
   * @param options.mode - Security mode (default: 'YOLO' to access private key)
   * @param options.tag - Tag for address derivation (default: 'MAIN')
   * @param options.requireAuth - Force WebAuthn re-authentication
   * @returns Encrypted payload that can be decrypted by sender or recipients
   *
   * @example
   * ```typescript
   * const w3pk = createWeb3Passkey();
   * await w3pk.login();
   *
   * // Get server's public key
   * const serverPubKey = await fetch('/api/mlkem-public-key').then(r => r.text());
   *
   * // Encrypt for yourself + server
   * const encrypted = await w3pk.mlkemEncrypt(
   *   'my secret data',
   *   [serverPubKey]
   * );
   *
   * // Later: decrypt with the same wallet
   * const decrypted = await w3pk.mlkemDecrypt(encrypted);
   * ```
   */
  async mlkemEncrypt(
    plaintext: string,
    recipientPublicKeys: Array<string | Uint8Array>,
    options?: {
      context?: string;
      mode?: SecurityMode;
      tag?: string;
      requireAuth?: boolean;
    }
  ): Promise<EncryptedPayload> {
    return mlkemEncrypt(this.ctx, plaintext, recipientPublicKeys, options);
  }

  /**
   * Decrypt ML-KEM encrypted data using current wallet
   *
   * Decrypts data that was encrypted for this wallet.
   * The hybrid keypair is derived from your wallet's private key. Only v3 payloads are read.
   *
   * @param payload - The encrypted payload (from mlkemEncrypt)
   * @param options - Optional configuration
   * @param options.context - Context string for key derivation (default: MLKEM_DEFAULT_CONTEXT, must match encryption)
   * @param options.mode - Security mode (default: 'YOLO' to access private key)
   * @param options.tag - Tag for address derivation (default: 'MAIN')
   * @param options.requireAuth - Force WebAuthn re-authentication
   * @returns Decrypted plaintext
   *
   * @example
   * ```typescript
   * const w3pk = createWeb3Passkey();
   * await w3pk.login();
   *
   * // Retrieve encrypted data
   * const encrypted = await fetch('/api/my-data').then(r => r.json());
   *
   * // Decrypt locally (server never sees plaintext!)
   * const plaintext = await w3pk.mlkemDecrypt(encrypted);
   * ```
   */
  async mlkemDecrypt(
    payload: EncryptedPayload,
    options?: {
      context?: string;
      mode?: SecurityMode;
      tag?: string;
      requireAuth?: boolean;
    }
  ): Promise<string> {
    return mlkemDecrypt(this.ctx, payload, options);
  }
}
