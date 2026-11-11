/**
 * Main Web3Passkey SDK
 *
 * SECURITY MODEL:
 * - Master mnemonic never exposed to applications
 * - Applications access only origin-specific derived wallets
 * - Three security modes for origin-centric derivation:
 *   - STANDARD: Address only (no private key), persistent sessions allowed
 *   - STRICT: Address only (no private key), no session
 *   - YOLO: Full access (address + private key), persistent sessions allowed
 * - Each origin receives isolated address derivation
 *
 * STEALTH ADDRESSES (opt-in via config.stealthAddresses):
 * - Applications receive the viewing key, never the spending key or a stealth
 *   private key; w3pk signs from stealth addresses after a fresh assertion
 * - Stealth keys are shared across origins
 * - Uses separate derivation: m/44'/60'/1'/0/0 and m/44'/60'/1'/0/1
 * - Not derived from origin-specific addresses
 */

import { register } from "../auth/register";
import { login } from "../auth/authenticate";
import {
  LocalStorageWalletStorage,
  openWalletRecord,
  sealWalletRecord,
} from "../wallet/storage";
import type { EncryptedWalletData } from "../wallet/types";
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
  verifyPublicKeyMac,
} from "../wallet/crypto";
import { StealthAddressModule } from "../stealth";
import { SessionManager, type SessionAccount } from "./session";
import { CredentialStorage } from "../auth/storage";
import {
  assertPrfSecretTag,
  derivePrfSecret,
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
import {
  W3PK_ACCOUNT_FACTORY,
  getCreateAccountCalldata,
  getSmartAccountAddress,
} from "../wallet/smart-account";
import {
  encodeTypedDataSignature,
  personalSignHash,
  typedDataSignPayload,
  wrapErc6492Signature,
} from "../wallet/erc7739";
import type { Provider } from "ethers";
import { signWithPasskey, stubWebAuthnSignature } from "../wallet/webauthn-signature";
import {
  type UserOperation,
  encodeExecute,
  getEntryPointNonce,
  getUserOperationHash,
  hasP256Precompile,
  P256_PRECOMPILE_GAS,
  P256_SOLIDITY_GAS,
} from "../wallet/user-operation";
import {
  checkUserOperationCaps,
  estimateUserOperationGas,
  getPaymasterData,
  getPaymasterStubData,
  sendUserOperation,
  waitForUserOperationReceipt,
} from "../wallet/bundler";
import { SIWE_HEADER, assertSiweDomain, parseSiweMessage } from "../siwe";
import { getSigningDigests, signableTypedData } from "./signing-digests";
import type {
  UserInfo,
  GeneratedWallet,
  DerivedWallet,
  RegisterResult,
  SecurityMode,
  SigningMethod,
  SignMessageOptions,
  TransactionRequest,
  SendTransactionOptions,
  SendTransactionResult,
} from "../types";
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
import {
  UnauthorizedError,
  UserRejectedRequestError,
  assertSigner,
  confirmBeforeSign,
  createEIP1193Provider,
  type EIP1193ProviderInterface,
  type EIP1193ProviderOptions,
  type TransactionBeforeSignDigests,
} from "./eip1193";
import type { SdkContext } from "./context";
import { bip39Seed, deriveMLKemPublicKey, mlkemDecrypt, mlkemEncrypt } from "./mlkem";
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

// A lenient decoder can't produce the ASCII header from invalid bytes, so a
// message without it in the lenient text isn't SIWE; one with it must be
// valid UTF-8, or a verifier decoding it leniently could accept it unchecked
function siweText(message: string | Uint8Array): string | undefined {
  if (typeof message === 'string') return message.includes(SIWE_HEADER) ? message : undefined;
  if (!new TextDecoder().decode(message).includes(SIWE_HEADER)) return undefined;
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(message);
  } catch {
    throw new WalletError("Invalid SIWE message: not valid UTF-8");
  }
}

export class Web3Passkey {
  private config: InternalConfig;
  private walletStorage: LocalStorageWalletStorage;
  private currentUser: UserInfo | null = null;
  /** The logged-in passkey's public key, as checked at login */
  private currentPublicKey: string | null = null;
  /** A wallet waiting for register(); cleared once the user is logged in */
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
      config.sessionDuration ?? DEFAULT_CONFIG.sessionDuration,
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
      get currentPublicKey() {
        return sdk.currentPublicKey;
      },
      set currentPublicKey(publicKey) {
        sdk.currentPublicKey = publicKey;
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
      this.zkModule = new ZKProofModule({
        ...this.config.zkProofs,
        nftHolderKey: (contractAddress) => this.deriveNFTHolderKey(contractAddress),
      });
      return this.zkModule;
    } catch (error) {
      throw new Error(
        "ZK module not available. Install the optional dependencies snarkjs and circomlibjs"
      );
    }
  }

  /** The NFT holder identity's private key, from the wallet in the session */
  private async deriveNFTHolderKey(contractAddress: string): Promise<Uint8Array> {
    const { deriveNFTHolderKey } = await import("../zk/semaphore");
    const origin = normalizeOrigin(getCurrentOrigin());
    const seed = await bip39Seed(await this.getMnemonicFromSession());
    try {
      return deriveNFTHolderKey(seed, origin, contractAddress);
    } finally {
      seed.fill(0);
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

    const walletData = await this.retrieveWallet(
      this.currentUser.credentialId,
      this.currentUser.ethereumAddress
    );

    if (!walletData) {
      throw new WalletError("No wallet found. Generate a wallet first.");
    }

    const authResult = await login(
      this.config.userVerification,
      this.currentUser.credentialId
    );
    if (!authResult.user) {
      throw new WalletError("Authentication failed");
    }
    // The record is encrypted under the logged-in passkey's PRF output
    if (authResult.user.credentialId !== this.currentUser.credentialId) {
      throw new WalletError("Authenticate with the logged-in passkey");
    }
    if (!authResult.prfOutput) {
      throw new PrfUnsupportedError(authResult.user.credentialId);
    }

    const mnemonic = await this.decryptWallet(walletData, authResult.prfOutput);

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
      this.sessionAccount(),
      prfSessionKey,
      effectiveMode
    );

    return mnemonic;
  }

  /** The logged-in account a persistent session is stored for */
  private sessionAccount(): SessionAccount | undefined {
    return this.currentUser && this.currentPublicKey
      ? { ethereumAddress: this.currentUser.ethereumAddress, publicKey: this.currentPublicKey }
      : undefined;
  }

  /**
   * The logged-in passkey's public key for PRIMARY mode, as checked at login:
   * never read again from storage, where it could have been changed since
   */
  private primaryPublicKey(): string {
    if (!this.currentPublicKey) {
      throw new WalletError("No WebAuthn credential found for PRIMARY mode");
    }
    return this.currentPublicKey;
  }

  /**
   * The passkey's wallet record, if it holds the wallet the passkey points
   * at: an interrupted address change can leave one without the other
   */
  private async retrieveWallet(
    credentialId: string,
    ethereumAddress: string
  ): Promise<EncryptedWalletData | null> {
    const walletData = await this.walletStorage.retrieve(credentialId);
    return walletData?.ethereumAddress.toLowerCase() === ethereumAddress.toLowerCase()
      ? walletData
      : null;
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
    await this.walletStorage.store(
      await sealWalletRecord(mnemonic, await deriveWalletKey(prfOutput), {
        ethereumAddress,
        credentialId,
        createdAt,
      })
    );
  }

  /**
   * Decrypt a wallet record with the key derived from `prfOutput`
   *
   * @throws CryptoError if the key is wrong or the record's metadata was changed
   */
  private async decryptWallet(
    walletData: EncryptedWalletData,
    prfOutput: BufferSource
  ): Promise<string> {
    return openWalletRecord(walletData, await deriveWalletKey(prfOutput));
  }

  /**
   * Register new user with WebAuthn
   * Automatically generates wallet if none exists and associates with passkey
   *
   * @throws PrfUnsupportedError if the authenticator returns no PRF output, at
   *   creation or in the one assertion after it: nothing is stored, and the
   *   passkey is signalled as unknown where the browser supports it
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

      const { credentialId, publicKey, prfOutput } = registration;

      this.currentUser = {
        username: options.username,
        ethereumAddress,
        credentialId,
      };
      this.currentPublicKey = publicKey;

      let prfSessionKey: CryptoKey;
      try {
        await this.storeWallet(ethereumAddress, mnemonic, credentialId, prfOutput);
        prfSessionKey = await derivePrfSessionKey(prfOutput, this.sessionManager.storesSessionKey);
      } finally {
        new Uint8Array(prfOutput).fill(0);
      }

      this.currentWallet = null;
      await this.sessionManager.startSession(
        mnemonic,
        credentialId,
        { ethereumAddress, publicKey },
        prfSessionKey,
        'STANDARD' // Default security mode for register
      );

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
        const walletData = await this.retrieveWallet(
          silentRestore.credentialId,
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
        this.currentPublicKey = silentRestore.publicKey;
        this.currentWallet = null;

        void this.requestPersistentStorage();
        this.config.onAuthStateChanged?.(true, this.currentUser);
        return this.currentUser;
      }

      // STEP 2: No silent restore - proceed with WebAuthn authentication
      const result = await login(this.config.userVerification);

      if (!result.verified || !result.user || !result.credential) {
        throw new AuthenticationError("Login failed");
      }

      const walletData = await this.retrieveWallet(
        result.user.credentialId,
        result.user.ethereumAddress
      );

      // Without PRF the wallet can't be decrypted here: it has to be
      // restored from a backup
      if (!walletData || !result.prfOutput) {
        throw new WalletMissingError(
          result.user.credentialId,
          result.user.ethereumAddress
        );
      }

      const { publicKey, publicKeyMac } = result.credential;
      if (!(await verifyPublicKeyMac(result.prfOutput, result.user.credentialId, publicKey, publicKeyMac))) {
        throw new AuthenticationError("The passkey's stored public key failed authentication");
      }

      this.currentUser = {
        username: result.user.username,
        ethereumAddress: result.user.ethereumAddress,
        credentialId: result.user.credentialId,
      };
      this.currentPublicKey = publicKey;
      const account = { ethereumAddress: result.user.ethereumAddress, publicKey };

      // Key derived from THIS assertion's PRF output: decrypts the existing
      // persistent session (deterministic PRF input → same key as when the
      // blob was written) and re-keys the next one
      const prfSessionKey = await derivePrfSessionKey(
        result.prfOutput,
        this.sessionManager.storesSessionKey
      );

      // Try to restore from persistent session first (if requireReauth is true)
      const restoredMnemonic = await this.sessionManager.restoreFromPersistentStorage(
        account,
        walletData.credentialId,
        prfSessionKey
      );

      if (!restoredMnemonic) {
        let mnemonic: string;
        try {
          mnemonic = await this.decryptWallet(walletData, result.prfOutput);
        } catch (error) {
          if (!(error instanceof CryptoError)) throw error;
          // Under another key, or edited in storage: it has to be restored
          // from a backup
          this.currentUser = null;
          this.currentPublicKey = null;
          throw new WalletMissingError(
            result.user.credentialId,
            result.user.ethereumAddress
          );
        }

        // Start new session with persistence
        await this.sessionManager.startSession(
          mnemonic,
          walletData.credentialId,
          account,
          prfSessionKey,
          'STANDARD' // Default security mode
        );
      }

      this.currentWallet = null;
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
    this.currentPublicKey = null;
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
   * - STRICT: Address only (no private key), no session (requires auth each time)
   * - YOLO: Full access (address + private key), persistent sessions allowed
   * - PRIMARY: Address of the passkey's P-256 smart account for the tag, deployed or not (no private key)
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

      // PRIMARY mode: the passkey's P-256 smart account
      if (effectiveMode === 'PRIMARY') {
        const publicKey = this.primaryPublicKey();
        const address = await getSmartAccountAddress(
          publicKey,
          effectiveTag,
          this.config.smartAccount
        );

        return {
          address,
          origin,
          mode: effectiveMode,
          tag: effectiveTag,
          publicKey,
        };
      }

      // STRICT mode: always require authentication (no session)
      const requireAuth = effectiveMode === 'STRICT' ? true : (options?.requireAuth || false);

      const mnemonic = await this.getMnemonicFromSession(requireAuth, effectiveMode);

      const derived = await getOriginSpecificAddress(mnemonic, origin, effectiveMode, effectiveTag);

      return {
        address: derived.address,
        privateKey: derived.privateKey,
        path: derived.path,
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
   * // Get PRIMARY address (the passkey's P-256 smart account, one per tag)
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

      // PRIMARY mode: the passkey's P-256 smart account
      if (effectiveMode === 'PRIMARY') {
        return await getSmartAccountAddress(
          this.primaryPublicKey(),
          effectiveTag,
          this.config.smartAccount
        );
      }

      // For other modes, derive from mnemonic
      // STRICT mode: always require authentication (no session)
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
   * the stored one in the passkey's record. If pointing the credential at
   * it fails, the previous record is put back. The previous wallet's
   * persistent session is deleted first.
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

      const authResult = await login(
        this.config.userVerification,
        this.currentUser.credentialId
      );
      if (authResult.credential?.id !== this.currentUser.credentialId) {
        throw new WalletError("Authenticate with the logged-in passkey to import a mnemonic");
      }
      if (!authResult.prfOutput) {
        throw new PrfUnsupportedError(this.currentUser.credentialId);
      }
      await bootstrapCredential(
        this.ctx,
        authResult.credential,
        phrase,
        ethereumAddress,
        authResult.prfOutput,
        true
      );
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
   * @param options.signingMethod - EIP191 (default), SIWE, EIP712 or rawHash;
   *   rawHash always requires a fresh user-verified passkey assertion, and is refused in PRIMARY mode
   * @param options.chainId - PRIMARY mode: chain the signature is bound to, required for EIP191
   * @param options.rpcUrl - PRIMARY mode: RPC endpoint used to check whether the account is deployed
   * @param options.from - Expected signer address, in any letter case: another throws
   *   UnauthorizedError (code 4100), unwrapped, before signing
   *
   * In PRIMARY mode the passkey signs an ERC-7739 signature for its P-256 smart account, which
   * verifies through EIP-1271 `isValidSignature`, or through ERC-6492 while the account isn't
   * deployed. Each signature asks for a fresh passkey assertion.
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

      // Through EIP-1271, a bare hash would skip ERC-7739's replay protection
      if (effectiveMode === 'PRIMARY' && signingMethod === 'rawHash') {
        throw new WalletError(
          "rawHash signing is not supported in PRIMARY mode. Use EIP191, SIWE or EIP712."
        );
      }

      const origin = getCurrentOrigin();

      // EIP-4361: reject a SIWE message whose domain isn't this page's, also
      // when it comes as a plain EIP-191 message, which signs the same bytes,
      // or as bytes that decode to one, as personal_sign passes hex
      const text =
        signingMethod === 'SIWE' ? (message as string)
        : signingMethod === 'EIP191' ? siweText(message)
        : undefined;
      if (text !== undefined) assertSiweDomain(text, origin);

      // Checked before the passkey prompt that rawHash always triggers
      if (signingMethod === 'rawHash' && !/^(0x)?[0-9a-fA-F]{64}$/.test(message as string)) {
        throw new WalletError("rawHash signing method requires a 32-byte hash (64 hex characters)");
      }

      if (!this.currentUser) {
        throw new WalletError("Must be authenticated to sign message");
      }

      const effectiveTag = options?.tag || DEFAULT_TAG;

      if (effectiveMode === 'PRIMARY') {
        return {
          ...(await this.signWithSmartAccount(message, signingMethod, effectiveTag, text, options)),
          origin,
        };
      }

      // STRICT mode: always require authentication (no session)
      // rawHash: a bare hash may be an EIP-7702 authorization digest, which
      // can't be told apart, so it gets the same fresh assertion as signAuthorization
      const requireAuth =
        effectiveMode === 'STRICT' || signingMethod === 'rawHash' || (options?.requireAuth || false);

      const mnemonic = await this.getMnemonicFromSession(requireAuth, effectiveMode);

      // Derive the wallet from the specified mode and tag
      const derived = await getOriginSpecificAddress(mnemonic, origin, effectiveMode, effectiveTag);
      assertSigner(derived.address, options?.from);

      const { Wallet } = await import("ethers");

      // If YOLO mode, we have the private key available
      let wallet: any;
      if (derived.privateKey) {
        wallet = new Wallet(derived.privateKey);
      } else {
        // For STANDARD/STRICT modes, derive from mnemonic at the origin path
        const { deriveWalletFromPath } = await import("../wallet/generate");
        const { privateKey } = deriveWalletFromPath(mnemonic, derived.path);
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

          const typedData = signableTypedData({
            domain: options.eip712Domain,
            types: options.eip712Types,
            primaryType: options.eip712PrimaryType,
            message: typedDataMessage,
          });
          signature = await wallet.signTypedData(typedData.domain, typedData.types, typedData.message);
          break;

        case 'rawHash':
          // Sign raw 32-byte hash without EIP-191 prefix
          // Useful for signing pre-computed EIP-712 hashes (e.g., Safe transactions)
          const { SigningKey } = await import("ethers");

          let hashToSign = message as string;
          if (hashToSign.startsWith('0x')) {
            hashToSign = hashToSign.slice(2);
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
      if (error instanceof UnauthorizedError) throw error;
      this.config.onError?.(error as any);
      throw new WalletError("Failed to sign message", error);
    }
  }

  /**
   * ERC-7739 signature of a message by the passkey's P-256 smart account, ERC-6492-wrapped
   * unless the account is known to be deployed
   */
  private async signWithSmartAccount(
    message: string | Uint8Array,
    signingMethod: SigningMethod,
    tag: string,
    siweText: string | undefined,
    options?: SignMessageOptions
  ): Promise<{ signature: string; address: string; mode: SecurityMode; tag: string }> {
    const publicKey = this.primaryPublicKey();
    const credentialId = this.currentUser!.credentialId;

    const domainChainId = options?.eip712Domain?.chainId;
    const siweChainId = siweText !== undefined ? parseSiweMessage(siweText).chainId : undefined;
    if (siweChainId !== undefined && options?.chainId !== undefined && siweChainId !== options.chainId) {
      throw new WalletError(`SIWE Chain ID ${siweChainId} does not match chainId ${options.chainId}`);
    }
    const chainId =
      options?.chainId ??
      siweChainId ??
      (signingMethod === 'EIP712' && domainChainId != null ? Number(domainChainId) : undefined);
    if (chainId === undefined) {
      throw new WalletError("PRIMARY mode signing requires options.chainId");
    }

    const address = await getSmartAccountAddress(publicKey, tag, this.config.smartAccount);
    assertSigner(address, options?.from);
    const account = { address, chainId };
    const { hashMessage } = await import("ethers");

    let signature: string;
    if (signingMethod === 'EIP712') {
      if (!options?.eip712Domain || !options?.eip712Types || !options?.eip712PrimaryType) {
        throw new WalletError("EIP712 signing requires eip712Domain, eip712Types, and eip712PrimaryType in options");
      }
      let typedDataMessage: Record<string, any>;
      try {
        typedDataMessage = JSON.parse(message as string);
      } catch {
        throw new WalletError("EIP712 message must be valid JSON or an object");
      }
      const typedData = signableTypedData({
        domain: options.eip712Domain,
        types: options.eip712Types,
        primaryType: options.eip712PrimaryType,
        message: typedDataMessage,
      });
      const payload = typedDataSignPayload(
        typedData.domain,
        typedData.types,
        typedData.primaryType,
        typedData.message,
        account
      );
      signature = encodeTypedDataSignature(
        await signWithPasskey(payload.challenge, credentialId),
        payload
      );
    } else {
      signature = await signWithPasskey(personalSignHash(hashMessage(message), account), credentialId);
    }

    if (!(await this.isDeployed(address, chainId, options?.rpcUrl))) {
      signature = wrapErc6492Signature(
        this.config.smartAccount?.factoryAddress ?? W3PK_ACCOUNT_FACTORY,
        await getCreateAccountCalldata(publicKey, tag),
        signature
      );
    }

    return { signature, address, mode: 'PRIMARY', tag };
  }

  /** Whether `address` has code; false when no RPC endpoint is set for the chain */
  private async isDeployed(address: string, chainId: number, rpcUrl?: string): Promise<boolean> {
    const url = rpcUrl ?? this.config.rpcUrls?.[chainId]?.[0];
    if (!url) return false;
    const { JsonRpcProvider } = await import("ethers");
    const provider = new JsonRpcProvider(url, chainId, { staticNetwork: true });
    try {
      return (await provider.getCode(address)) !== "0x";
    } finally {
      provider.destroy();
    }
  }

  /**
   * Send a transaction using the derived wallet for the current security mode
   *
   * In PRIMARY mode the passkey's P-256 smart account sends it as an ERC-4337
   * UserOperation (EntryPoint v0.9) through a bundler, deploying the account
   * with its first transaction on the chain. An array of transactions is
   * executed atomically, in one UserOperation. The account pays its own gas,
   * unless an ERC-7677 paymaster service is set. Gas values or a max fee above
   * the chain's `userOperationCaps` throw before the passkey prompt.
   *
   * @param tx - Transaction, or in PRIMARY mode an array of transactions on the same chain
   * @param tx.to - Recipient address
   * @param tx.value - Value in wei (optional)
   * @param tx.data - Hex calldata (optional, default "0x")
   * @param tx.chainId - Chain ID (required)
   * @param tx.gasLimit - Gas limit override (optional); in PRIMARY mode the UserOperation's
   *   callGasLimit is the larger of the bundler's estimate and the sum of the gasLimits
   * @param tx.maxFeePerGas - EIP-1559 max fee per gas (optional)
   * @param tx.maxPriorityFeePerGas - EIP-1559 max priority fee per gas (optional)
   * @param tx.gasPrice - Legacy gas price (optional), not with the EIP-1559 fees; on an
   *   EIP-1559 chain, and in PRIMARY mode, it is both the max fee and the max priority fee
   * @param tx.nonce - Nonce override (optional, ignored in PRIMARY mode: the EntryPoint sets it)
   * @param options.mode - Security mode (default: STANDARD)
   * @param options.tag - Wallet tag (optional)
   * @param options.requireAuth - Force fresh authentication (optional)
   * @param options.rpcUrl - RPC endpoint override (optional); without it, the first
   *   `rpcUrls` endpoint set for the chain is used. Throws if neither is set:
   *   chainid.network endpoints are never used to send
   * @param options.bundlerUrl - PRIMARY mode: bundler endpoint (default: `bundlerUrls[chainId]`)
   * @param options.onBeforeSign - Awaited with the transaction's ERC-8213 digests (getSigningDigests())
   *   and `method: "eth_sendTransaction"`, an array of them for an array of transactions, before the
   *   passkey prompt; in PRIMARY mode each also carries the UserOperation's `maxFee` in wei; throw, reject or return `false` to cancel with UserRejectedRequestError (code 4001).
   *   The transactions are copied first, and the copy is sent
   * @param options.from - Expected sender address, in any letter case: another throws
   *   UnauthorizedError (code 4100), unwrapped, before signing
   * @param options.paymasterUrl - PRIMARY mode: ERC-7677 paymaster service (default: `paymasterUrl`)
   * @param options.paymasterContext - PRIMARY mode: ERC-7677 context (default: {})
   * @param options.timeout - PRIMARY mode: inclusion timeout in ms (default: 60000)
   * @returns Transaction hash and metadata; in PRIMARY mode, the hash of the
   *   transaction that included the UserOperation, and its `userOpHash`
   *
   * @example
   * const result = await w3pk.sendTransaction({ to: "0x...", value: 1000000000000000000n, chainId: 1 })
   * console.log(result.hash)
   */
  async sendTransaction(
    tx: TransactionRequest | TransactionRequest[],
    options?: SendTransactionOptions
  ): Promise<SendTransactionResult> {
    try {
      if (!this.currentUser) {
        throw new WalletError("Must be authenticated to send transaction");
      }

      const effectiveMode = options?.mode || DEFAULT_MODE;
      const effectiveTag = options?.tag || DEFAULT_TAG;
      const origin = getCurrentOrigin();
      const snapshot = Array.isArray(tx) ? tx.map((t) => ({ ...t })) : { ...tx };
      const txs = Array.isArray(snapshot) ? snapshot : [snapshot];
      const confirm = (maxFee?: bigint) => this.confirmTransaction(snapshot, options?.onBeforeSign, maxFee);
      if (txs.some((t) => t.gasPrice !== undefined && (t.maxFeePerGas !== undefined || t.maxPriorityFeePerGas !== undefined))) {
        throw new WalletError("gasPrice can't be set with maxFeePerGas or maxPriorityFeePerGas");
      }

      if (effectiveMode === 'PRIMARY') {
        const ops = txs.map(({ gasPrice, ...t }) =>
          gasPrice === undefined ? t : { ...t, maxFeePerGas: gasPrice, maxPriorityFeePerGas: gasPrice }
        );
        return await this.sendWithSmartAccount(ops, effectiveTag, origin, confirm, options);
      }
      if (Array.isArray(tx)) {
        throw new WalletError("Only PRIMARY mode sends an array of transactions");
      }
      const [request] = txs;

      const rpcUrl = this.getRpcUrl(request.chainId, options?.rpcUrl);
      await confirm();

      // STRICT mode: always require authentication (no session)
      const requireAuth = effectiveMode === 'STRICT' ? true : (options?.requireAuth || false);

      const mnemonic = await this.getMnemonicFromSession(requireAuth, effectiveMode);

      // Derive the wallet from the specified mode and tag
      const derived = await getOriginSpecificAddress(mnemonic, origin, effectiveMode, effectiveTag);
      assertSigner(derived.address, options?.from);

      const { Wallet, JsonRpcProvider } = await import("ethers");

      // If YOLO mode, we have the private key available
      let wallet: any;
      if (derived.privateKey) {
        wallet = new Wallet(derived.privateKey);
      } else {
        // For STANDARD/STRICT modes, derive from mnemonic at the origin path
        const { deriveWalletFromPath } = await import("../wallet/generate");
        const { privateKey } = deriveWalletFromPath(mnemonic, derived.path);
        wallet = new Wallet(privateKey);
      }

      const provider = new JsonRpcProvider(rpcUrl);
      const connected = wallet.connect(provider);

      const response = await connected.sendTransaction({
        to: request.to,
        value: request.value,
        data: request.data ?? "0x",
        chainId: request.chainId,
        gasLimit: request.gasLimit,
        maxFeePerGas: request.maxFeePerGas,
        maxPriorityFeePerGas: request.maxPriorityFeePerGas,
        gasPrice: request.gasPrice,
        nonce: request.nonce,
      });

      return {
        hash: response.hash,
        from: derived.address,
        chainId: request.chainId,
        mode: derived.mode,
        tag: derived.tag,
        origin: derived.origin,
      };
    } catch (error) {
      if (error instanceof UserRejectedRequestError || error instanceof UnauthorizedError) throw error;
      this.config.onError?.(error as any);
      const reason = (error as any)?.shortMessage ?? (error instanceof Error ? error.message : String(error));
      throw new WalletError(`Failed to send transaction: ${reason}`, error);
    }
  }

  /**
   * Awaits onBeforeSign with the digests of a transaction, or of each of an
   * array of transactions, and in PRIMARY mode the UserOperation's max fee
   */
  private async confirmTransaction(
    tx: TransactionRequest | TransactionRequest[],
    onBeforeSign: SendTransactionOptions["onBeforeSign"],
    maxFee?: bigint
  ): Promise<void> {
    if (!onBeforeSign) return;
    const digestsOf = ({ to, value, data }: TransactionRequest): TransactionBeforeSignDigests => ({
      method: "eth_sendTransaction",
      ...getSigningDigests({ method: "eth_sendTransaction", params: [{ to, value, data }] }),
      ...(maxFee !== undefined && { maxFee }),
    });
    await confirmBeforeSign(onBeforeSign, Array.isArray(tx) ? tx.map(digestsOf) : digestsOf(tx));
  }

  private primarySends = new Map<string, Promise<void>>();

  /**
   * Runs PRIMARY sends of one account and chain one after another: the
   * EntryPoint nonce only advances on inclusion, and ERC-4337 lets a bundler
   * refuse a second UserOperation from an unstaked sender
   */
  private queuePrimarySend<T>(key: string, send: () => Promise<T>): Promise<T> {
    const result = (this.primarySends.get(key) ?? Promise.resolve()).then(send);
    const settled = result.then(
      () => {},
      () => {}
    );
    this.primarySends.set(key, settled);
    settled.then(() => {
      if (this.primarySends.get(key) === settled) this.primarySends.delete(key);
    });
    return result;
  }

  private p256Precompile = new Map<number, Promise<boolean>>();

  /** Whether the chain has the EIP-7951 precompile, checked once per chain */
  private hasP256Precompile(chainId: number, provider: Pick<Provider, "call">): Promise<boolean> {
    let result = this.p256Precompile.get(chainId);
    if (!result) {
      result = hasP256Precompile(provider);
      this.p256Precompile.set(chainId, result);
    }
    return result;
  }

  private getRpcUrl(chainId: number, rpcUrl?: string): string {
    const url = rpcUrl ?? this.config.rpcUrls?.[chainId]?.[0];
    if (!url) {
      throw new WalletError(
        `No RPC endpoint set for chainId ${chainId}. Set rpcUrls in the config ` +
        `(rpcUrls: { ${chainId}: ['https://...'] }) or pass options.rpcUrl.`
      );
    }
    return url;
  }

  /**
   * Sends calls from the passkey's P-256 smart account as one EntryPoint v0.9
   * UserOperation, and waits for its inclusion
   */
  private async sendWithSmartAccount(
    txs: TransactionRequest[],
    tag: string,
    origin: string,
    confirm: (maxFee: bigint) => Promise<void>,
    options?: SendTransactionOptions
  ): Promise<SendTransactionResult> {
    if (txs.length === 0) {
      throw new WalletError("No transaction to send");
    }
    const chainId = txs[0].chainId;
    if (txs.some((t) => t.chainId !== chainId)) {
      throw new WalletError("All batched transactions must be on the same chain");
    }
    for (const key of ['maxFeePerGas', 'maxPriorityFeePerGas'] as const) {
      if (new Set(txs.map((t) => t[key])).size > 1) {
        throw new WalletError(`All batched transactions must have the same ${key}`);
      }
    }

    const bundlerUrl = options?.bundlerUrl ?? this.config.bundlerUrls?.[chainId];
    if (!bundlerUrl) {
      throw new WalletError(
        `No bundler set for chainId ${chainId}. Set bundlerUrls in the config ` +
        `(bundlerUrls: { ${chainId}: 'https://...' }) or pass options.bundlerUrl.`
      );
    }
    const rpcUrl = this.getRpcUrl(chainId, options?.rpcUrl);
    const paymasterUrl = options?.paymasterUrl ?? this.config.paymasterUrl;
    const paymasterContext = options?.paymasterContext ?? {};

    const credentialId = this.currentUser!.credentialId;
    return this.queuePrimarySend(`${credentialId}:${tag}:${chainId}`, async () => {
      const publicKey = this.primaryPublicKey();
      const sender = await getSmartAccountAddress(publicKey, tag, this.config.smartAccount);
      assertSigner(sender, options?.from);

      const { JsonRpcProvider } = await import("ethers");
      const provider = new JsonRpcProvider(rpcUrl, chainId, { staticNetwork: true });
      let op: UserOperation;
      let maxFee: bigint;
      try {
        const [code, nonce, feeData, precompile] = await Promise.all([
          provider.getCode(sender),
          getEntryPointNonce(provider, sender),
          txs[0].maxFeePerGas !== undefined && txs[0].maxPriorityFeePerGas !== undefined
            ? null
            : provider.getFeeData(),
          this.hasP256Precompile(chainId, provider),
        ]);
        const maxFeePerGas = txs[0].maxFeePerGas ?? feeData?.maxFeePerGas;
        let maxPriorityFeePerGas = txs[0].maxPriorityFeePerGas ?? feeData?.maxPriorityFeePerGas;
        if (maxFeePerGas == null || maxPriorityFeePerGas == null) {
          throw new WalletError(`Chain ${chainId} reports no EIP-1559 fees`);
        }
        if (maxPriorityFeePerGas > maxFeePerGas) {
          if (txs[0].maxPriorityFeePerGas !== undefined) {
            throw new WalletError("maxPriorityFeePerGas is above maxFeePerGas");
          }
          maxPriorityFeePerGas = maxFeePerGas;
        }

        op = {
          sender,
          nonce,
          callData: encodeExecute(txs),
          callGasLimit: 0n,
          verificationGasLimit: 0n,
          preVerificationGas: 0n,
          maxFeePerGas,
          maxPriorityFeePerGas,
          signature: stubWebAuthnSignature(window.location.origin),
        };
        if (code === "0x") {
          op.factory = this.config.smartAccount?.factoryAddress ?? W3PK_ACCOUNT_FACTORY;
          op.factoryData = await getCreateAccountCalldata(publicKey, tag);
        }

        let isFinal = false;
        if (paymasterUrl) {
          const stub = await getPaymasterStubData(paymasterUrl, op, chainId, paymasterContext);
          Object.assign(op, {
            paymaster: stub.paymaster,
            paymasterData: stub.paymasterData ?? "0x",
            paymasterVerificationGasLimit: stub.paymasterVerificationGasLimit ?? 0n,
            paymasterPostOpGasLimit: stub.paymasterPostOpGasLimit ?? 0n,
          });
          if (!stub.paymaster) {
            throw new WalletError("The paymaster service returned no paymaster");
          }
          isFinal = stub.isFinal === true;
        }

        const gas = await estimateUserOperationGas(bundlerUrl, op);
        op.preVerificationGas = gas.preVerificationGas;
        const gasLimit = txs.reduce((sum, t) => sum + (t.gasLimit ?? 0n), 0n);
        op.callGasLimit = gas.callGasLimit > gasLimit ? gas.callGasLimit : gasLimit;
        // The stub signature fails the challenge check before the P-256 verification runs
        op.verificationGasLimit =
          gas.verificationGasLimit + (precompile ? P256_PRECOMPILE_GAS : P256_SOLIDITY_GAS);
        if (op.paymaster) {
          op.paymasterVerificationGasLimit ||= gas.paymasterVerificationGasLimit ?? 0n;
          op.paymasterPostOpGasLimit ||= gas.paymasterPostOpGasLimit ?? 0n;
        }

        maxFee = checkUserOperationCaps(op, this.config.userOperationCaps?.[chainId]);

        if (paymasterUrl && !isFinal) {
          const data = await getPaymasterData(paymasterUrl, op, chainId, paymasterContext);
          op.paymaster = data.paymaster ?? op.paymaster;
          op.paymasterData = data.paymasterData ?? "0x";
        }
      } finally {
        provider.destroy();
      }

      await confirm(maxFee);
      op.signature = await signWithPasskey(getUserOperationHash(op, chainId), credentialId);
      const userOpHash = await sendUserOperation(bundlerUrl, op);
      const receipt = await waitForUserOperationReceipt(bundlerUrl, userOpHash, { timeout: options?.timeout });

      return {
        hash: receipt.receipt.transactionHash,
        userOpHash,
        from: sender,
        chainId,
        mode: 'PRIMARY',
        tag,
        origin,
      };
    });
  }

  /**
   * Sign EIP-7702 authorization for gasless transactions
   * Allows EOA to delegate execution to contract for gas sponsorship
   *
   * @param params.contractAddress - Contract address to authorize
   * @param params.chainId - Chain ID (default: 1)
   * @param params.nonce - Nonce (default: 0)
   * @param options.mode - Security mode of the signing wallet (default: STANDARD, PRIMARY is refused)
   * @param options.tag - Wallet tag (default: MAIN)
   *
   * Signs with the origin-specific derived key (never the master key) after a
   * fresh user-verified passkey assertion.
   */
  async signAuthorization(
    params: {
      contractAddress: string;
      chainId?: number;
      nonce?: bigint;
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

      if ('privateKey' in params) {
        throw new WalletError(
          "signAuthorization() takes no privateKey: it signs with the origin-derived key for options.mode and options.tag"
        );
      }

      const { Wallet, Signature } = await import("ethers");
      const { hashEIP7702AuthorizationMessage, verifyEIP7702Authorization } = await import("../eip7702/utils");

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

      let wallet: any;
      if (derived.privateKey) {
        wallet = new Wallet(derived.privateKey);
      } else {
        const { deriveWalletFromPath } = await import("../wallet/generate");
        const { privateKey } = deriveWalletFromPath(mnemonic, derived.path);
        wallet = new Wallet(privateKey);
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
   * chainid.network endpoints that need no API key (skipped if chainid.network
   * can't be reached and the app set endpoints for the chain)
   */
  async getEndpoints(chainId: number): Promise<string[]> {
    const appEndpoints = this.config.rpcUrls?.[chainId] ?? [];
    const chainlist = appEndpoints.length > 0
      ? await getEndpoints(chainId).catch(() => [])
      : await getEndpoints(chainId);
    return [...new Set([...appEndpoints, ...chainlist])];
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
   * - eth_accounts / eth_requestAccounts  → getAddress() for the mode and tag
   * - eth_chainId                          → from options.chainId (default: 1)
   * - eth_sendTransaction                  → delegates to sendTransaction()
   * - personal_sign / eth_sign            → delegates to signMessage() EIP-191
   * - eth_signTypedData_v4                → delegates to signMessage() EIP-712
   * - wallet_switchEthereumChain          → updates the active chainId
   * - eth_blockNumber, eth_call, eth_estimateGas, eth_getBalance, eth_getCode,
   *   eth_getStorageAt, eth_getTransactionCount, eth_getTransactionByHash,
   *   eth_getTransactionReceipt, eth_getBlockByNumber, eth_getBlockByHash,
   *   eth_getLogs, eth_gasPrice, eth_maxPriorityFeePerGas, eth_feeHistory,
   *   net_version                         → forwarded to the active chain's RPC endpoint
   *
   * Read methods go to options.rpcUrl on the initial chain, otherwise to
   * `rpcUrls[chainId][0]` from the config, and throw before any request if
   * neither is set. JSON-RPC errors pass through with their code and data.
   * Any other method rejects with error 4200.
   *
   * The account a signing request names (eth_sendTransaction's `from`, the
   * address of personal_sign, eth_sign and eth_signTypedData_v4) is required:
   * a missing or malformed one rejects with error -32602 (Invalid params),
   * another than eth_accounts' with error 4100 (Unauthorized) before signing,
   * in any letter case.
   *
   * eth_sendTransaction reads `input` as `data`, and rejects both with error
   * -32602 when they differ. It sends a legacy `gasPrice`, and rejects it with
   * error -32602 alongside `maxFeePerGas` or `maxPriorityFeePerGas`.
   *
   * In PRIMARY mode the passkey's P-256 smart account sends ERC-4337
   * UserOperations and signs ERC-7739 signatures bound to the active chain;
   * the EOA `nonce` is ignored, `gas` raises the UserOperation's
   * callGasLimit, `gasPrice` sets both its fees, and eth_sign rejects with error 4200: through EIP-1271, a
   * bare hash would skip ERC-7739's replay protection.
   *
   * With options.onBeforeSign, eth_sendTransaction, eth_signTypedData_v4,
   * personal_sign and eth_sign compute their ERC-8213 digests and await the
   * hook before the passkey prompt. If it throws, rejects or returns false,
   * the request rejects with error 4001 (User Rejected Request), the hook's
   * error as `cause`, and nothing is signed. In PRIMARY mode, eth_sendTransaction's
   * digests also carry the UserOperation's `maxFee` in wei. The host app controls both the
   * request and the hook, so the digests are only worth checking on a second, independent tool.
   *
   * @param options.mode       - Security mode for signing/sending (default: 'STANDARD')
   * @param options.tag        - Wallet tag (default: 'MAIN')
   * @param options.chainId    - Initial chainId reported to consumers (default: 1)
   * @param options.rpcUrl     - RPC endpoint for read methods, sendTransaction() and, in PRIMARY mode, signMessage() (default: `rpcUrls[chainId][0]`)
   * @param options.bundlerUrl - PRIMARY mode: bundler endpoint (default: `bundlerUrls[chainId]`)
   * @param options.onBeforeSign - Awaited with the request's ERC-8213 digests (getSigningDigests()) and its `method`, after the request is validated and before the passkey prompt; throw, reject or return `false` to cancel with error 4001
   *
   * rpcUrl and bundlerUrl serve options.chainId only: after
   * wallet_switchEthereumChain, the config's rpcUrls and bundlerUrls for the new chain are used.
   *
   * @example
   * // ethers v6
   * const provider = new BrowserProvider(w3pk.getEIP1193Provider())
   *
   * // viem
   * const client = createWalletClient({ transport: custom(w3pk.getEIP1193Provider()) })
   *
   * // show the digests before the passkey prompt
   * const provider = w3pk.getEIP1193Provider({
   *   onBeforeSign: (digests) => confirmDigests(digests), // false cancels
   * })
   *
   * // wagmi (custom connector)
   * const connector = injected({ target: () => ({ id: 'w3pk', provider: w3pk.getEIP1193Provider() }) })
   */
  getEIP1193Provider(options?: EIP1193ProviderOptions): EIP1193ProviderInterface {
    return createEIP1193Provider(this, options, (chainId) => this.config.rpcUrls?.[chainId]?.[0]);
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
   * Creates a password backup (BackupFile v4, Argon2id): the backup that
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
   * Combines M-of-N guardian shares to reconstruct the backup file, then
   * restores it as restoreFromBackupFile() restores a password backup:
   * logged out, the wallet stays in memory for register(); logged in, it
   * replaces the stored wallet after a passkey assertion. The mnemonic is
   * never returned.
   *
   * @param shares - Array of guardian share objects (JSON strings or parsed objects)
   * @param password - Password of the backup the shares rebuild
   * @throws AddressChangeError when logged in with another address, without `allowAddressChange`
   * @throws InvalidGuardianShareError naming a corrupted, edited, mixed-up or old-format share
   */
  async recoverFromGuardians(
    shares: Array<string | GuardianShare>,
    password: string,
    options?: { allowAddressChange?: boolean }
  ): Promise<{ ethereumAddress: string }> {
    return recoverFromGuardians(this.ctx, shares, password, options);
  }

  /**
   * Restore wallet from backup file with existing passkey
   * Use case: User has passkey synced to this device
   *
   * When logged out, a restored password backup stays in memory: call
   * register() to create a passkey for it, or log in and restore the file
   * again to store it under that passkey. The mnemonic is never returned.
   *
   * A PRF backup takes one assertion with its passkey, no password, and sets
   * this device up for that passkey (as importFromSync() does).
   *
   * When logged in, the restored wallet replaces the stored one only after
   * the passkey assertion succeeds. A backup of another address than the
   * logged-in one needs `allowAddressChange: true`, which the app sets once
   * the user confirms the replacement.
   *
   * @throws UnsupportedBackupVersionError for a file that isn't BackupFile v4
   * @throws SyncBootstrapError ('CREDENTIAL_MISMATCH') for a PRF backup of another passkey than the logged-in one
   * @throws AddressChangeError for a backup of another address without `allowAddressChange`
   * @throws AuthenticationError if the passkey prompt is cancelled, and PrfUnsupportedError if the authenticator returns no PRF output, when logged in (nothing stored changes)
   */
  async restoreFromBackupFile(
    backupData: string | Blob,
    password?: string,
    options?: { allowAddressChange?: boolean }
  ): Promise<{ ethereumAddress: string }> {
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
   * A backup of another address than the one this device stores for the
   * passkey needs `allowAddressChange: true`, which the app sets once the
   * user confirms the replacement.
   *
   * @param backupData - Backup file (JSON string or Blob) - can be pasted by user
   * @param password - Password to decrypt backup (if password-encrypted)
   * @returns The restored wallet's address (the mnemonic is never returned)
   * @throws AddressChangeError for a backup of another address than the passkey's, without `allowAddressChange` (nothing stored changes)
   */
  async syncWalletWithPasskey(
    backupData: string | Blob,
    password?: string,
    options?: { allowAddressChange?: boolean }
  ): Promise<{ ethereumAddress: string }> {
    return syncWalletWithPasskey(this.ctx, backupData, password, options);
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
   * A backup of another address than the one this device stores for the
   * passkey needs `allowAddressChange: true`, which the app sets once the
   * user confirms the replacement.
   *
   * @throws SyncBootstrapError ('CREDENTIAL_MISMATCH') when logged in with another passkey
   * @throws AddressChangeError for a backup of another address than the passkey's, without `allowAddressChange` (nothing stored changes)
   */
  async importFromSync(
    syncData: string | Blob,
    options?: { allowAddressChange?: boolean }
  ): Promise<{ ethereumAddress: string; success: boolean }> {
    return importFromSync(this.ctx, syncData, options);
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
   * Only public signals equal to the secret or a random input are refused:
   * the circuit chooses its public signals and can output any function of
   * the secret, the Semaphore secret included. Only prove with circuits
   * you trust; the artifact pins say which circuit runs, not what it reveals.
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
   * The hybrid keypair is derived deterministically from the wallet's BIP-39 seed,
   * the current origin, the mode, the tag and the context.
   *
   * @param options - Optional configuration
   * @param options.context - Context string for domain separation (default: MLKEM_DEFAULT_CONTEXT)
   * @param options.mode - Security mode (default: 'STANDARD')
   * @param options.tag - Tag (default: 'MAIN')
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
   * Payloads have no sender authentication: every recipient learns the shared data key,
   * so any recipient can seal new content for the others. To prove you wrote the content,
   * sign the plaintext, the recipients' public keys and a timestamp with `signMessage()`,
   * encrypt the signed message, and have recipients verify the signature against your
   * address after decrypting. Signing the ciphertext doesn't work: anyone can strip the
   * signature and sign it as themselves. See docs/POST_QUANTUM.md.
   *
   * @param plaintext - The data to encrypt
   * @param recipientPublicKeys - Array of recipient hybrid public keys (base64 strings or Uint8Arrays, 1600 bytes)
   * @param options - Optional configuration
   * @param options.context - Context string for key derivation (default: MLKEM_DEFAULT_CONTEXT)
   * @param options.mode - Security mode (default: 'STANDARD')
   * @param options.tag - Tag (default: 'MAIN')
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
   * The hybrid keypair is derived from your wallet's BIP-39 seed. Only v3 payloads are read.
   * Decryption doesn't prove who sent the payload: any recipient can seal new content for
   * the others, so verify the sender's signature inside the payload (see `mlkemEncrypt()`).
   *
   * @param payload - The encrypted payload (from mlkemEncrypt)
   * @param options - Optional configuration
   * @param options.context - Context string for key derivation (default: MLKEM_DEFAULT_CONTEXT, must match encryption)
   * @param options.mode - Security mode (default: 'STANDARD')
   * @param options.tag - Tag (default: 'MAIN')
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
