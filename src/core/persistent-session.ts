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
import { encodeFields } from "../utils/crypto";
import { decryptData, encryptData } from "../wallet/crypto";

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
  /** WebAuthn credential ID (used as key) */
  credentialId: string;
  /** User's ethereum address */
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

const SESSION_AAD_LABEL = "w3pk-session-record-v1";

type SessionMetadata = Omit<PersistentSessionData, "encryptedMnemonic" | "sessionKey">;

/**
 * AES-GCM additional data of a session record: every field but the
 * ciphertext and the key, so a record whose expiry, address or credential
 * was edited in storage fails to decrypt
 */
function sessionAdditionalData(record: SessionMetadata): Uint8Array<ArrayBuffer> {
  return encodeFields(
    SESSION_AAD_LABEL,
    record.credentialId,
    record.ethereumAddress,
    String(record.expiresAt),
    record.securityMode,
    String(record.createdAt)
  );
}

/** Encrypt `mnemonic` under `key` into a session record bound to `metadata` */
export async function sealSessionRecord(
  mnemonic: string,
  key: CryptoKey,
  metadata: SessionMetadata
): Promise<Omit<PersistentSessionData, "sessionKey">> {
  const { credentialId, ethereumAddress, expiresAt, securityMode, createdAt } = metadata;
  return {
    credentialId,
    ethereumAddress,
    expiresAt,
    securityMode,
    createdAt,
    encryptedMnemonic: await encryptData(mnemonic, key, sessionAdditionalData(metadata)),
  };
}

/**
 * Decrypt a session record's mnemonic
 *
 * @throws CryptoError if `key` is wrong or the record's metadata was changed
 */
export function openSessionRecord(record: PersistentSessionData, key: CryptoKey): Promise<string> {
  return decryptData(record.encryptedMnemonic, key, sessionAdditionalData(record));
}

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
      this.storage.setItem(KEY_PREFIX + data.credentialId, JSON.stringify(data));
    } catch (error) {
      throw new StorageError("Failed to store persistent session", error);
    }
  }

  /**
   * Retrieve a passkey's persistent session
   */
  async retrieve(credentialId: string): Promise<PersistentSessionData | null> {
    let session: PersistentSessionData | null;
    try {
      const raw = this.storage.getItem(KEY_PREFIX + credentialId);
      session = raw ? (JSON.parse(raw) as PersistentSessionData) : null;
    } catch (error) {
      throw new StorageError("Failed to retrieve persistent session", error);
    }

    // Auto-cleanup expired sessions
    if (session && Date.now() > session.expiresAt) {
      await this.delete(credentialId);
      return null;
    }

    return session;
  }

  /**
   * Delete a persistent session
   */
  async delete(credentialId: string): Promise<void> {
    try {
      this.storage.removeItem(KEY_PREFIX + credentialId);
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
