/**
 * Persistent Session Storage
 *
 * Enables "Remember Me" functionality for STANDARD and YOLO mode wallets.
 *
 * SECURITY:
 * - The mnemonic blob is encrypted with a key derived from the WebAuthn PRF
 *   extension: a secret the authenticator releases only during a
 *   user-verified assertion. Nothing stored on disk can re-derive it.
 * - requireReauth: true  → the key is NOT stored; every restore re-evaluates
 *   the PRF on a live assertion. The blob is hardware-bound at rest.
 * - requireReauth: false → the raw key is stored next to the blob so silent
 *   restore works without a prompt, and re-imported as non-extractable. Any
 *   script on the origin can read it, which adds little: it could already
 *   use a stored key to decrypt. It is refreshed at every real (prompted)
 *   login.
 * - Authenticators without PRF get no persistent sessions (in-memory only) —
 *   there is deliberately no weaker fallback encryption.
 * - Only enabled for STANDARD and YOLO modes (STRICT mode excluded)
 * - Time-limited expiration; the expiry IS the renewal boundary: when the
 *   blob expires, the next login prompts, and that assertion's PRF output
 *   re-keys a fresh blob.
 */

import { StorageError } from "./errors";
import type { SecurityMode } from "../types";

/**
 * Persistent session data stored in localStorage
 */
export interface PersistentSessionData {
  /** Mnemonic encrypted under the PRF-derived AES-GCM key */
  encryptedMnemonic: string;
  /**
   * The PRF-derived key as base64url, stored ONLY when silent restore is
   * enabled (requireReauth: false). Absent when requireReauth is true —
   * decryption then requires a fresh user-verified assertion.
   */
  sessionKey?: string;
  /** Expiration timestamp */
  expiresAt: number;
  /** WebAuthn credential ID */
  credentialId: string;
  /** User's ethereum address (used as key) */
  ethereumAddress: string;
  /** Security mode for this session */
  securityMode: SecurityMode;
  /** Timestamp when session was created */
  createdAt: number;
}

/**
 * Configuration for persistent sessions
 */
export interface PersistentSessionConfig {
  /** Enable persistent sessions (default: false for backward compatibility) */
  enabled: boolean;
  /** Duration in hours (default: 7 days = 168 hours) */
  duration: number;
  /** Require re-authentication on page refresh (default: true for security) */
  requireReauth: boolean;
}

const KEY_PREFIX = "w3pk_session_";

/**
 * Manages persistent sessions in localStorage, next to the credential
 * metadata so browser eviction removes both or neither
 *
 * Only stores sessions for STANDARD and YOLO modes.
 * STRICT mode sessions are never persisted.
 */
export class PersistentSessionStorage {
  constructor(private readonly customStorage?: Storage) {}

  private get storage(): Storage {
    if (this.customStorage) return this.customStorage;
    if (typeof window !== "undefined" && window.localStorage) {
      return window.localStorage;
    }
    throw new StorageError("localStorage is not available");
  }

  async init(): Promise<void> {}

  /**
   * Store a persistent session
   * Only called for STANDARD and YOLO modes
   */
  async store(data: PersistentSessionData): Promise<void> {
    // Security check: Never persist STRICT mode sessions
    if (data.securityMode === 'STRICT') {
      throw new StorageError("Cannot persist STRICT mode sessions");
    }

    try {
      this.storage.setItem(KEY_PREFIX + data.ethereumAddress, JSON.stringify(data));
    } catch (error) {
      throw new StorageError("Failed to store persistent session", error);
    }
  }

  /**
   * Retrieve a persistent session by ethereum address
   */
  async retrieve(ethereumAddress: string): Promise<PersistentSessionData | null> {
    let session: PersistentSessionData | null;
    try {
      const raw = this.storage.getItem(KEY_PREFIX + ethereumAddress);
      session = raw ? (JSON.parse(raw) as PersistentSessionData) : null;
    } catch (error) {
      throw new StorageError("Failed to retrieve persistent session", error);
    }

    // Auto-cleanup expired sessions
    if (session && Date.now() > session.expiresAt) {
      await this.delete(ethereumAddress);
      return null;
    }

    return session;
  }

  /**
   * Delete a persistent session
   */
  async delete(ethereumAddress: string): Promise<void> {
    try {
      this.storage.removeItem(KEY_PREFIX + ethereumAddress);
    } catch (error) {
      throw new StorageError("Failed to delete persistent session", error);
    }
  }

  /**
   * Clear all persistent sessions
   */
  async clear(): Promise<void> {
    try {
      for (const key of this.keys()) {
        this.storage.removeItem(key);
      }
    } catch (error) {
      throw new StorageError("Failed to clear persistent sessions", error);
    }
  }

  /**
   * Clean up expired sessions
   */
  async cleanupExpired(): Promise<void> {
    try {
      const now = Date.now();
      for (const key of this.keys()) {
        const raw = this.storage.getItem(key);
        const session = raw ? (JSON.parse(raw) as PersistentSessionData) : null;
        if (!session || now > session.expiresAt) {
          this.storage.removeItem(key);
        }
      }
    } catch (error) {
      throw new StorageError("Failed to cleanup expired sessions", error);
    }
  }

  private keys(): string[] {
    const keys: string[] = [];
    for (let i = 0; i < this.storage.length; i++) {
      const key = this.storage.key(i);
      if (key?.startsWith(KEY_PREFIX)) keys.push(key);
    }
    return keys;
  }
}
