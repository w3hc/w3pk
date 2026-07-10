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
 * - requireReauth: false → the key is stored as a NON-EXTRACTABLE CryptoKey
 *   so silent restore works without a prompt. Scripts can use it but never
 *   read its bytes; it is refreshed at every real (prompted) login.
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
 * Persistent session data stored in IndexedDB
 */
export interface PersistentSessionData {
  /** Mnemonic encrypted under the PRF-derived AES-GCM key */
  encryptedMnemonic: string;
  /**
   * The PRF-derived key, stored ONLY when silent restore is enabled
   * (requireReauth: false). Non-extractable: IndexedDB persists the CryptoKey
   * object itself via structured clone, never exposing raw bytes to scripts.
   * Absent when requireReauth is true — decryption then requires a fresh
   * user-verified assertion.
   */
  sessionKey?: CryptoKey;
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

const DB_NAME = "Web3PasskeyPersistentSessions";
// v3: PRF-keyed encryption. Old records were encrypted under keys derivable
// from stored data (credentialId + publicKey) — they are dropped, not
// migrated. Users re-key with one normal login.
const DB_VERSION = 3;
const STORE_NAME = "sessions";

/**
 * Manages persistent sessions in IndexedDB
 *
 * Only stores sessions for STANDARD and YOLO modes.
 * STRICT mode sessions are never persisted.
 */
export class PersistentSessionStorage {
  private db: IDBDatabase | null = null;
  private initPromise: Promise<void> | null = null;

  async init(): Promise<void> {
    // Prevent multiple simultaneous init calls (race condition fix)
    if (this.initPromise) {
      return this.initPromise;
    }

    if (this.db) {
      return Promise.resolve();
    }

    this.initPromise = new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      // Set onupgradeneeded IMMEDIATELY (before onsuccess/onerror)
      // This ensures the object store is created before the database opens
      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        // Pre-v3 records are encrypted under keys derivable from stored data:
        // drop them wholesale instead of migrating
        if (db.objectStoreNames.contains(STORE_NAME)) {
          db.deleteObjectStore(STORE_NAME);
        }
        const store = db.createObjectStore(STORE_NAME, { keyPath: "ethereumAddress" });
        // Index by expiration for cleanup
        store.createIndex("expiresAt", "expiresAt", { unique: false });
      };

      request.onsuccess = () => {
        this.db = request.result;
        this.initPromise = null;
        resolve();
      };

      request.onerror = () => {
        this.initPromise = null;
        reject(new StorageError("Failed to open persistent session database", request.error));
      };
    });

    return this.initPromise;
  }

  /**
   * Store a persistent session
   * Only called for STANDARD and YOLO modes
   */
  async store(data: PersistentSessionData): Promise<void> {
    // Security check: Never persist STRICT mode sessions
    if (data.securityMode === 'STRICT') {
      throw new StorageError("Cannot persist STRICT mode sessions");
    }

    if (!this.db) await this.init();

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction([STORE_NAME], "readwrite");
      const store = transaction.objectStore(STORE_NAME);

      const request = store.put(data);
      request.onerror = () =>
        reject(new StorageError("Failed to store persistent session", request.error));
      request.onsuccess = () => resolve();
    });
  }

  /**
   * Retrieve a persistent session by ethereum address
   */
  async retrieve(ethereumAddress: string): Promise<PersistentSessionData | null> {
    if (!this.db) await this.init();

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction([STORE_NAME], "readonly");
      const store = transaction.objectStore(STORE_NAME);

      const request = store.get(ethereumAddress);
      request.onerror = () =>
        reject(new StorageError("Failed to retrieve persistent session", request.error));
      request.onsuccess = () => {
        const session = request.result || null;

        // Auto-cleanup expired sessions
        if (session && Date.now() > session.expiresAt) {
          this.delete(ethereumAddress).catch(console.error);
          resolve(null);
          return;
        }

        resolve(session);
      };
    });
  }

  /**
   * Delete a persistent session
   */
  async delete(ethereumAddress: string): Promise<void> {
    if (!this.db) await this.init();

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction([STORE_NAME], "readwrite");
      const store = transaction.objectStore(STORE_NAME);

      const request = store.delete(ethereumAddress);
      request.onerror = () =>
        reject(new StorageError("Failed to delete persistent session", request.error));
      request.onsuccess = () => resolve();
    });
  }

  /**
   * Clear all persistent sessions
   */
  async clear(): Promise<void> {
    if (!this.db) await this.init();

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction([STORE_NAME], "readwrite");
      const store = transaction.objectStore(STORE_NAME);

      const request = store.clear();
      request.onerror = () =>
        reject(new StorageError("Failed to clear persistent sessions", request.error));
      request.onsuccess = () => resolve();
    });
  }

  /**
   * Clean up expired sessions
   */
  async cleanupExpired(): Promise<void> {
    if (!this.db) await this.init();

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction([STORE_NAME], "readwrite");
      const store = transaction.objectStore(STORE_NAME);
      const index = store.index("expiresAt");

      const now = Date.now();
      const range = IDBKeyRange.upperBound(now);
      const request = index.openCursor(range);

      request.onsuccess = (event) => {
        const cursor = (event.target as IDBRequest).result;
        if (cursor) {
          cursor.delete();
          cursor.continue();
        } else {
          resolve();
        }
      };

      request.onerror = () =>
        reject(new StorageError("Failed to cleanup expired sessions", request.error));
    });
  }
}

