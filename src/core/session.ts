/**
 * Session Manager - Caches decrypted mnemonic for configurable duration
 *
 * SECURITY:
 * - In-memory sessions: Mnemonic is stored in RAM only (cleared on page refresh)
 * - Persistent sessions: Encrypted mnemonic stored in IndexedDB (survives page refresh)
 * - Persistent sessions ONLY for STANDARD and YOLO modes (STRICT mode excluded)
 * - Automatically cleared after session expires
 * - Can be manually revoked at any time
 *
 * AUTHENTICATION MODES:
 * - requireReauth: true (default): Biometric prompt on every page refresh (more secure)
 * - requireReauth: false: Silent session restore without prompt (maximum convenience)
 */

import type { SecurityMode } from "../types";
import type { PersistentSessionConfig } from "./persistent-session";
import {
  PersistentSessionStorage,
  encryptMnemonicForPersistence,
  decryptMnemonicFromPersistence,
} from "./persistent-session";

export interface SessionData {
  mnemonic: string;
  expiresAt: string;
  credentialId: string;
}

export class SessionManager {
  private session: SessionData | null = null;
  private sessionDuration: number; // in milliseconds
  private persistentConfig: PersistentSessionConfig;
  private persistentStorage: PersistentSessionStorage;

  constructor(
    sessionDurationHours: number = 1,
    persistentConfig?: Partial<PersistentSessionConfig>
  ) {
    this.sessionDuration = sessionDurationHours * 60 * 60 * 1000; // Convert to ms
    this.persistentConfig = {
      enabled: persistentConfig?.enabled ?? false,
      duration: persistentConfig?.duration ?? 168, // 7 days default
      requireReauth: persistentConfig?.requireReauth ?? true,
    };
    this.persistentStorage = new PersistentSessionStorage();
  }

  /**
   * Start a new session with the decrypted mnemonic
   * Optionally persists session to IndexedDB for STANDARD/YOLO modes
   *
   * @param mnemonic - The decrypted mnemonic
   * @param credentialId - WebAuthn credential ID
   * @param ethereumAddress - User's ethereum address
   * @param publicKey - WebAuthn public key for encryption
   * @param securityMode - Security mode (STRICT sessions are never persisted)
   */
  async startSession(
    mnemonic: string,
    credentialId: string,
    ethereumAddress?: string,
    publicKey?: string,
    securityMode?: SecurityMode
  ): Promise<void> {
    const expiresAt = new Date(Date.now() + this.sessionDuration).toISOString();
    this.session = {
      mnemonic,
      expiresAt,
      credentialId,
    };

    // Persist session if enabled and not STRICT mode
    if (
      this.persistentConfig.enabled &&
      securityMode !== 'STRICT' &&
      ethereumAddress &&
      publicKey
    ) {
      try {
        const encryptedMnemonic = await encryptMnemonicForPersistence(
          mnemonic,
          credentialId,
          publicKey
        );

        const persistentExpiresAt =
          Date.now() + this.persistentConfig.duration * 60 * 60 * 1000;

        await this.persistentStorage.store({
          encryptedMnemonic,
          expiresAt: persistentExpiresAt,
          credentialId,
          ethereumAddress,
          securityMode: securityMode || 'STANDARD',
          createdAt: Date.now(),
        });
      } catch (error) {
        // Non-fatal: continue with in-memory session if persistence fails
        console.warn('[w3pk] Failed to persist session:', error);
      }
    }
  }

  /**
   * Get the cached mnemonic if session is still valid
   * Returns null if session expired or doesn't exist
   */
  getMnemonic(): string | null {
    if (!this.session) {
      return null;
    }

    // Check if session expired
    if (new Date() > new Date(this.session.expiresAt)) {
      this.clearSession();
      return null;
    }

    return this.session.mnemonic;
  }

  /**
   * Get session credential ID
   */
  getCredentialId(): string | null {
    if (!this.session) {
      return null;
    }

    if (new Date() > new Date(this.session.expiresAt)) {
      this.clearSession();
      return null;
    }

    return this.session.credentialId;
  }

  /**
   * Check if session is active and valid
   */
  isActive(): boolean {
    return this.getMnemonic() !== null;
  }

  /**
   * Get remaining session time in seconds
   */
  getRemainingTime(): number {
    if (!this.session) {
      return 0;
    }

    if (new Date() > new Date(this.session.expiresAt)) {
      this.clearSession();
      return 0;
    }

    return Math.floor((new Date(this.session.expiresAt).getTime() - Date.now()) / 1000);
  }

  /**
   * Extend the session by the configured duration
   */
  extendSession(): void {
    if (!this.session) {
      throw new Error("No active session to extend");
    }

    if (new Date() > new Date(this.session.expiresAt)) {
      this.clearSession();
      throw new Error("Session expired, cannot extend");
    }

    this.session.expiresAt = new Date(Date.now() + this.sessionDuration).toISOString();
  }

  /**
   * Restore session from persistent storage
   * Returns decrypted mnemonic if persistent session exists and is valid
   *
   * @param ethereumAddress - User's ethereum address
   * @param credentialId - WebAuthn credential ID
   * @param publicKey - WebAuthn public key for decryption
   * @returns Mnemonic if session restored, null otherwise
   */
  async restoreFromPersistentStorage(
    ethereumAddress: string,
    credentialId: string,
    publicKey: string
  ): Promise<string | null> {
    if (!this.persistentConfig.enabled) {
      return null;
    }

    try {
      const persistentSession = await this.persistentStorage.retrieve(ethereumAddress);

      if (!persistentSession) {
        return null;
      }

      // Verify credential ID matches
      if (persistentSession.credentialId !== credentialId) {
        console.warn('[w3pk] Credential ID mismatch, clearing persistent session');
        await this.persistentStorage.delete(ethereumAddress);
        return null;
      }

      // Decrypt mnemonic
      const mnemonic = await decryptMnemonicFromPersistence(
        persistentSession.encryptedMnemonic,
        credentialId,
        publicKey
      );

      // Start in-memory session with restored mnemonic
      const expiresAt = new Date(Date.now() + this.sessionDuration).toISOString();
      this.session = {
        mnemonic,
        expiresAt,
        credentialId,
      };

      return mnemonic;
    } catch (error) {
      console.warn('[w3pk] Failed to restore persistent session:', error);
      // Clean up corrupted session
      try {
        await this.persistentStorage.delete(ethereumAddress);
      } catch {}
      return null;
    }
  }

  /**
   * Attempt silent session restore without requiring WebAuthn prompt
   * Only works if requireReauth is false and a valid persistent session exists
   *
   * @returns User info if session restored, null otherwise
   */
  async attemptSilentRestore(): Promise<{
    mnemonic: string;
    ethereumAddress: string;
    credentialId: string;
    publicKey: string;
  } | null> {
    // Only attempt silent restore if enabled and requireReauth is false
    if (!this.persistentConfig.enabled || this.persistentConfig.requireReauth) {
      return null;
    }

    try {
      // We need to check all stored credentials and their persistent sessions
      // Import CredentialStorage to get stored credentials
      const { CredentialStorage } = await import('../auth/storage');
      const credentialStorage = new CredentialStorage();
      const credentials = await credentialStorage.getAllCredentials();

      if (credentials.length === 0) {
        return null;
      }

      // Try to restore from each credential's persistent session
      // Usually there's only one, but we check all to be safe
      for (const credential of credentials) {
        const persistentSession = await this.persistentStorage.retrieve(
          credential.ethereumAddress
        );

        if (!persistentSession) {
          continue;
        }

        // Verify credential ID matches
        if (persistentSession.credentialId !== credential.id) {
          console.warn('[w3pk] Credential ID mismatch, skipping this session');
          continue;
        }

        // Decrypt mnemonic
        const mnemonic = await decryptMnemonicFromPersistence(
          persistentSession.encryptedMnemonic,
          credential.id,
          credential.publicKey
        );

        // Start in-memory session with restored mnemonic
        const expiresAt = new Date(Date.now() + this.sessionDuration).toISOString();
        this.session = {
          mnemonic,
          expiresAt,
          credentialId: credential.id,
        };

        return {
          mnemonic,
          ethereumAddress: credential.ethereumAddress,
          credentialId: credential.id,
          publicKey: credential.publicKey,
        };
      }

      return null;
    } catch (error) {
      console.warn('[w3pk] Failed to attempt silent restore:', error);
      return null;
    }
  }

  /**
   * Manually clear the session (logout or security requirement)
   * Also clears persistent session if address provided
   */
  async clearSession(ethereumAddress?: string): Promise<void> {
    // Overwrite mnemonic in memory before clearing
    if (this.session) {
      this.session.mnemonic = "0".repeat(this.session.mnemonic.length);
    }
    this.session = null;

    // Clear persistent session if address provided
    if (ethereumAddress && this.persistentConfig.enabled) {
      try {
        await this.persistentStorage.delete(ethereumAddress);
      } catch (error) {
        console.warn('[w3pk] Failed to clear persistent session:', error);
      }
    }
  }

  /**
   * Update session duration (affects new sessions and extensions)
   */
  setSessionDuration(hours: number): void {
    this.sessionDuration = hours * 60 * 60 * 1000;
  }
}
