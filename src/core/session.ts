/**
 * Session Manager - Caches decrypted mnemonic for configurable duration
 *
 * SECURITY:
 * - In-memory sessions: Mnemonic is stored in RAM only (cleared on page refresh)
 * - Persistent sessions: Mnemonic encrypted under a WebAuthn-PRF-derived key
 *   in IndexedDB (survives page refresh). PRF-capable authenticators only —
 *   no PRF, no persistence, no weaker fallback.
 * - Persistent sessions ONLY for STANDARD and YOLO modes (STRICT mode excluded)
 * - Automatically cleared after session expires
 * - Can be manually revoked at any time
 *
 * AUTHENTICATION MODES:
 * - requireReauth: true (default): Biometric prompt on every page refresh; the
 *   decryption key is re-derived from that assertion's PRF output and never
 *   stored — the blob is hardware-bound at rest
 * - requireReauth: false: Silent restore without prompt via a stored
 *   NON-EXTRACTABLE CryptoKey, re-keyed at every real (prompted) login
 */

import type { SecurityMode } from "../types";
import type { PersistentSessionConfig } from "./persistent-session";
import { PersistentSessionStorage } from "./persistent-session";
import { encryptData, decryptData } from "../wallet/crypto";

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
   * Persistence requires a PRF session key, which only exists when the
   * session started from a real user-verified assertion on a PRF-capable
   * authenticator. Without it the session is in-memory only — silent
   * remember-me is a PRF-gated feature, never downgraded to weaker crypto.
   *
   * @param mnemonic - The decrypted mnemonic
   * @param credentialId - WebAuthn credential ID
   * @param ethereumAddress - User's ethereum address
   * @param prfSessionKey - Non-extractable AES key derived from this
   *   assertion's PRF output (see derivePrfSessionKey)
   * @param securityMode - Security mode (STRICT sessions are never persisted)
   */
  async startSession(
    mnemonic: string,
    credentialId: string,
    ethereumAddress?: string,
    prfSessionKey?: CryptoKey,
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
      ethereumAddress
    ) {
      if (!prfSessionKey) {
        console.info(
          '[w3pk] Authenticator did not provide a PRF output — persistent ' +
            'session not stored on this device (in-memory session only)'
        );
        return;
      }

      try {
        const encryptedMnemonic = await encryptData(mnemonic, prfSessionKey);

        const persistentExpiresAt =
          Date.now() + this.persistentConfig.duration * 60 * 60 * 1000;

        await this.persistentStorage.store({
          encryptedMnemonic,
          // Key stored only for silent restore; with requireReauth the next
          // assertion re-derives it, keeping the blob hardware-bound at rest
          sessionKey: this.persistentConfig.requireReauth ? undefined : prfSessionKey,
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
      // Fire-and-forget: expiry cleanup has no caller to surface errors to
      this.clearSession().catch((error) =>
        console.warn('[w3pk] Failed to clear expired session:', error)
      );
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
      // Fire-and-forget: expiry cleanup has no caller to surface errors to
      this.clearSession().catch((error) =>
        console.warn('[w3pk] Failed to clear expired session:', error)
      );
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
      // Fire-and-forget: expiry cleanup has no caller to surface errors to
      this.clearSession().catch((error) =>
        console.warn('[w3pk] Failed to clear expired session:', error)
      );
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
      // Fire-and-forget: expiry cleanup has no caller to surface errors to
      this.clearSession().catch((error) =>
        console.warn('[w3pk] Failed to clear expired session:', error)
      );
      throw new Error("Session expired, cannot extend");
    }

    this.session.expiresAt = new Date(Date.now() + this.sessionDuration).toISOString();
  }

  /**
   * Restore session from persistent storage after a user-verified assertion
   * Returns decrypted mnemonic if persistent session exists and is valid
   *
   * The caller passes the key derived from the CURRENT assertion's PRF
   * output. The PRF input is fixed, so the authenticator returns the same
   * secret it returned when the blob was encrypted — no key ever touches
   * disk on this path.
   *
   * @param ethereumAddress - User's ethereum address
   * @param credentialId - WebAuthn credential ID
   * @param prfSessionKey - Key derived from this assertion's PRF output
   * @returns Mnemonic if session restored, null otherwise
   */
  async restoreFromPersistentStorage(
    ethereumAddress: string,
    credentialId: string,
    prfSessionKey?: CryptoKey
  ): Promise<string | null> {
    if (!this.persistentConfig.enabled || !prfSessionKey) {
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

      // Decrypt mnemonic with the assertion-derived key
      const mnemonic = await decryptData(
        persistentSession.encryptedMnemonic,
        prfSessionKey
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
   * Only works if requireReauth is false and a valid persistent session
   * exists with a stored (non-extractable) session key
   *
   * @returns User info if session restored, null otherwise
   */
  async attemptSilentRestore(): Promise<{
    mnemonic: string;
    ethereumAddress: string;
    credentialId: string;
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

        // Silent restore needs the stored non-extractable key; records
        // written under requireReauth deliberately don't have one
        if (!persistentSession.sessionKey) {
          continue;
        }

        // Decrypt mnemonic with the stored non-extractable key
        const mnemonic = await decryptData(
          persistentSession.encryptedMnemonic,
          persistentSession.sessionKey
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
   * Also clears ALL persistent sessions from IndexedDB
   *
   * The in-memory session is always cleared, even if clearing persistent
   * storage fails — in that case a StorageError is thrown so callers know
   * a persistent session may still exist on the device
   *
   * @throws {StorageError} if persistent sessions could not be cleared
   */
  async clearSession(): Promise<void> {
    // Overwrite mnemonic in memory before clearing
    if (this.session) {
      this.session.mnemonic = "0".repeat(this.session.mnemonic.length);
    }
    this.session = null;

    // Clear ALL persistent sessions from IndexedDB on logout
    // This ensures no WebAuthn prompts appear after logout
    if (this.persistentConfig.enabled) {
      await this.persistentStorage.clear();
    }
  }

  /**
   * Update session duration (affects new sessions and extensions)
   */
  setSessionDuration(hours: number): void {
    this.sessionDuration = hours * 60 * 60 * 1000;
  }

  /**
   * Update persistent-session duration (affects sessions persisted from now
   * on; the currently stored blob keeps its original expiry until the next
   * real login re-keys it)
   */
  setPersistentSessionDuration(hours: number): void {
    this.persistentConfig.duration = hours;
  }
}
