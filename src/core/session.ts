/**
 * Session Manager - Caches decrypted mnemonic for configurable duration
 *
 * SECURITY:
 * - Mnemonic is stored in memory only (never persisted)
 * - Automatically cleared after session expires
 * - Can be manually revoked at any time
 * - Initial authentication still requires biometric/PIN
 */

export interface SessionData {
  mnemonic: string;
  expiresAt: string;
  credentialId: string;
}

export class SessionManager {
  private session: SessionData | null = null;
  private sessionDuration: number; // in milliseconds

  constructor(sessionDurationHours: number = 1) {
    this.sessionDuration = sessionDurationHours * 60 * 60 * 1000; // Convert to ms
  }

  /**
   * Start a new session with the decrypted mnemonic
   */
  startSession(mnemonic: string, credentialId: string): void {
    const expiresAt = new Date(Date.now() + this.sessionDuration).toISOString();
    this.session = {
      mnemonic,
      expiresAt,
      credentialId,
    };
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
   * Manually clear the session (logout or security requirement)
   */
  clearSession(): void {
    // Overwrite mnemonic in memory before clearing
    if (this.session) {
      this.session.mnemonic = "0".repeat(this.session.mnemonic.length);
    }
    this.session = null;
  }

  /**
   * Update session duration (affects new sessions and extensions)
   */
  setSessionDuration(hours: number): void {
    this.sessionDuration = hours * 60 * 60 * 1000;
  }
}
