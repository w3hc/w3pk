/**
 * localStorage Storage for Backup Metadata
 */

import type { BackupMetadata, BackupMethod } from './types';

const STORAGE_KEY = 'w3pk_backups';

export class BackupStorage {
  constructor(private readonly customStorage?: Storage) {}

  private get storage(): Storage | null {
    if (this.customStorage) return this.customStorage;
    if (typeof window !== 'undefined' && window.localStorage) {
      return window.localStorage;
    }
    return null; // Non-browser environment
  }

  async init(): Promise<void> {}

  /**
   * Store backup metadata
   */
  async storeBackupMetadata(metadata: BackupMetadata): Promise<void> {
    const backups = this.readAll().filter((b) => b.id !== metadata.id);
    backups.push(metadata);
    this.writeAll(backups);
  }

  /**
   * Get all backups for an address
   */
  async getBackupsByAddress(
    ethereumAddress: string
  ): Promise<BackupMetadata[]> {
    return this.readAll().filter((b) => b.ethereumAddress === ethereumAddress);
  }

  /**
   * Get backup by ID
   */
  async getBackupById(id: string): Promise<BackupMetadata | null> {
    return this.readAll().find((b) => b.id === id) ?? null;
  }

  /**
   * Delete backup metadata
   */
  async deleteBackup(id: string): Promise<void> {
    this.writeAll(this.readAll().filter((b) => b.id !== id));
  }

  /**
   * Get count of backups by method
   */
  async getBackupCountByMethod(
    method: BackupMethod
  ): Promise<number> {
    return this.readAll().filter((b) => b.method === method).length;
  }

  private readAll(): BackupMetadata[] {
    const raw = this.storage?.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as BackupMetadata[]) : [];
  }

  private writeAll(backups: BackupMetadata[]): void {
    this.storage?.setItem(STORAGE_KEY, JSON.stringify(backups));
  }
}
