/**
 * Persistent Session Storage
 *
 * Enables "Remember Me" functionality for STANDARD and YOLO mode wallets.
 *
 * SECURITY:
 * - Sessions encrypted with WebAuthn-derived keys
 * - Only enabled for STANDARD and YOLO modes (STRICT mode excluded)
 * - Time-limited expiration
 * - Origin-isolated via IndexedDB
 * - Requires valid WebAuthn credential to decrypt
 */

import { StorageError, CryptoError } from "./errors";
import { encryptData, decryptData, deriveEncryptionKeyFromWebAuthn } from "../wallet/crypto";
import type { SecurityMode } from "../types";

/**
 * Persistent session data stored in IndexedDB
 */
export interface PersistentSessionData {
  /** Encrypted mnemonic for session recovery */
  encryptedMnemonic: string;
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
const DB_VERSION = 2; // Incremented to force recreation of broken databases
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
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          const store = db.createObjectStore(STORE_NAME, { keyPath: "ethereumAddress" });
          // Index by expiration for cleanup
          store.createIndex("expiresAt", "expiresAt", { unique: false });
        }
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

/**
 * Encrypt mnemonic for persistent storage
 */
export async function encryptMnemonicForPersistence(
  mnemonic: string,
  credentialId: string,
  publicKey: string
): Promise<string> {
  try {
    const encryptionKey = await deriveEncryptionKeyFromWebAuthn(credentialId, publicKey);
    return await encryptData(mnemonic, encryptionKey);
  } catch (error) {
    throw new CryptoError("Failed to encrypt mnemonic for persistence", error);
  }
}

/**
 * Decrypt mnemonic from persistent storage
 */
export async function decryptMnemonicFromPersistence(
  encryptedMnemonic: string,
  credentialId: string,
  publicKey: string
): Promise<string> {
  try {
    const encryptionKey = await deriveEncryptionKeyFromWebAuthn(credentialId, publicKey);
    return await decryptData(encryptedMnemonic, encryptionKey);
  } catch (error) {
    throw new CryptoError("Failed to decrypt mnemonic from persistence", error);
  }
}
