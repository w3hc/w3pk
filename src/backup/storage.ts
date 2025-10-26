/**
 * IndexedDB Storage for Backup Metadata
 */

import type { BackupMetadata } from './types';

export class BackupStorage {
  private dbName = 'Web3PasskeyBackup';
  private version = 1;
  private db: IDBDatabase | null = null;

  /**
   * Initialize the database
   */
  async init(): Promise<void> {
    // Skip initialization in non-browser environments
    if (typeof indexedDB === 'undefined') {
      return Promise.resolve();
    }

    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.version);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        this.db = request.result;
        resolve();
      };

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;

        // Create backups object store
        if (!db.objectStoreNames.contains('backups')) {
          const store = db.createObjectStore('backups', { keyPath: 'id' });
          store.createIndex('ethereumAddress', 'ethereumAddress', {
            unique: false,
          });
          store.createIndex('method', 'method', { unique: false });
          store.createIndex('createdAt', 'createdAt', { unique: false });
        }
      };
    });
  }

  /**
   * Store backup metadata
   */
  async storeBackupMetadata(metadata: BackupMetadata): Promise<void> {
    if (!this.db) await this.init();
    if (!this.db) return Promise.resolve(); // Non-browser environment

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(['backups'], 'readwrite');
      const store = transaction.objectStore('backups');
      const request = store.put(metadata);

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Get all backups for an address
   */
  async getBackupsByAddress(
    ethereumAddress: string
  ): Promise<BackupMetadata[]> {
    if (!this.db) await this.init();
    if (!this.db) return Promise.resolve([]); // Non-browser environment

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(['backups'], 'readonly');
      const store = transaction.objectStore('backups');
      const index = store.index('ethereumAddress');
      const request = index.getAll(ethereumAddress);

      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Get backup by ID
   */
  async getBackupById(id: string): Promise<BackupMetadata | null> {
    if (!this.db) await this.init();
    if (!this.db) return Promise.resolve(null); // Non-browser environment

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(['backups'], 'readonly');
      const store = transaction.objectStore('backups');
      const request = store.get(id);

      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Delete backup metadata
   */
  async deleteBackup(id: string): Promise<void> {
    if (!this.db) await this.init();
    if (!this.db) return Promise.resolve(); // Non-browser environment

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(['backups'], 'readwrite');
      const store = transaction.objectStore('backups');
      const request = store.delete(id);

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Get count of backups by method
   */
  async getBackupCountByMethod(
    method: 'zip' | 'qr' | 'file'
  ): Promise<number> {
    if (!this.db) await this.init();
    if (!this.db) return Promise.resolve(0); // Non-browser environment

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction(['backups'], 'readonly');
      const store = transaction.objectStore('backups');
      const index = store.index('method');
      const request = index.count(method);

      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }
}
