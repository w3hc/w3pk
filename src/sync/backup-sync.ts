/**
 * Cross-Device Sync Manager
 *
 * Syncs wallets across devices where passkey is already synced.
 * Use case: User has passkey on mobile and desktop, but wallet only on desktop.
 * They can export wallet data from desktop and import on mobile.
 */

import type { BackupFile } from '../backup/types';

export interface DeviceSyncInfo {
  deviceName: string;
  platform: 'ios' | 'android' | 'macos' | 'windows' | 'linux' | 'unknown';
  lastSyncTime: string;
  walletsSynced: string[]; // Ethereum addresses
}

export class DeviceSyncManager {
  private readonly SYNC_STORAGE_KEY = 'w3pk_sync_info';

  /**
   * Get current device's sync information
   */
  async getSyncInfo(): Promise<DeviceSyncInfo | null> {
    try {
      const data = localStorage.getItem(this.SYNC_STORAGE_KEY);
      if (!data) return null;
      return JSON.parse(data) as DeviceSyncInfo;
    } catch (error) {
      console.error('Failed to get sync info:', error);
      return null;
    }
  }

  /**
   * Update sync information after successful import
   */
  async updateSyncInfo(ethereumAddress: string): Promise<void> {
    const info = await this.getSyncInfo();
    const platform = this.detectPlatform();

    const updated: DeviceSyncInfo = {
      deviceName: info?.deviceName || this.generateDeviceName(),
      platform,
      lastSyncTime: new Date().toISOString(),
      walletsSynced: info?.walletsSynced || [],
    };

    // Add address if not already present
    if (!updated.walletsSynced.includes(ethereumAddress)) {
      updated.walletsSynced.push(ethereumAddress);
    }

    localStorage.setItem(this.SYNC_STORAGE_KEY, JSON.stringify(updated));
  }

  /**
   * Detect current platform
   */
  private detectPlatform(): DeviceSyncInfo['platform'] {
    const userAgent = navigator.userAgent.toLowerCase();

    if (/iphone|ipad|ipod/.test(userAgent)) return 'ios';
    if (/android/.test(userAgent)) return 'android';
    if (/mac/.test(userAgent)) return 'macos';
    if (/win/.test(userAgent)) return 'windows';
    if (/linux/.test(userAgent)) return 'linux';

    return 'unknown';
  }

  /**
   * Generate device name
   */
  private generateDeviceName(): string {
    const platform = this.detectPlatform();
    const timestamp = new Date().toISOString().split('T')[0];

    return `${platform}-device-${timestamp}`;
  }

  /**
   * Export wallet for cross-device sync
   * Uses passkey encryption so it can be decrypted on any device where the passkey is synced
   */
  async exportForSync(
    mnemonic: string,
    ethereumAddress: string,
    credentialId: string,
    publicKey: string
  ): Promise<{ backupFile: BackupFile; json: string; blob: Blob }> {
    const { BackupFileManager } = await import('../backup/backup-file');
    const manager = new BackupFileManager();

    return manager.createPasskeyBackup(
      mnemonic,
      ethereumAddress,
      credentialId,
      publicKey
    );
  }

  /**
   * Import wallet from another device
   * Verifies that the passkey is synced and can decrypt the data
   */
  async importFromSync(
    backupFile: BackupFile,
    credentialId: string,
    publicKey: string
  ): Promise<{ mnemonic: string; ethereumAddress: string }> {
    const { BackupFileManager } = await import('../backup/backup-file');
    const manager = new BackupFileManager();

    const result = await manager.restoreWithExistingPasskey(
      backupFile,
      credentialId,
      publicKey
    );

    // Update sync info
    await this.updateSyncInfo(result.ethereumAddress);

    return result;
  }

  /**
   * Check if a backup file can be synced to this device
   * (i.e., check if we have the passkey that can decrypt it)
   */
  async canSyncBackup(
    backupFile: BackupFile,
    availableCredentials: Array<{ id: string; publicKeyFingerprint: string }>
  ): Promise<boolean> {
    if (backupFile.encryptionMethod !== 'passkey') {
      // Password-based backups can be synced with password
      return true;
    }

    if (!backupFile.publicKeyFingerprint) {
      // Can't verify without fingerprint
      return false;
    }

    // Check if we have a matching credential
    return availableCredentials.some(
      cred => cred.publicKeyFingerprint === backupFile.publicKeyFingerprint
    );
  }

  /**
   * Generate QR code for easy transfer between devices
   * Useful for syncing from desktop to mobile
   */
  async generateSyncQR(backupFile: BackupFile): Promise<string> {
    try {
      // Dynamic import to avoid bundling if not needed
      const QRCode = await import('qrcode');

      const json = JSON.stringify(backupFile);

      // Check size - QR codes have limits
      if (json.length > 2953) {
        // ~Version 40 QR code with high error correction
        throw new Error(
          'Backup file too large for QR code. Use file transfer instead.'
        );
      }

      return QRCode.toDataURL(json, {
        errorCorrectionLevel: 'H',
        margin: 2,
        width: 512,
      });
    } catch (error) {
      if ((error as any).code === 'ERR_MODULE_NOT_FOUND') {
        throw new Error(
          'QR code generation requires qrcode package: npm install qrcode'
        );
      }
      throw error;
    }
  }

  /**
   * Parse QR code data into backup file
   */
  async parseSyncQR(qrData: string): Promise<BackupFile> {
    const { BackupFileManager } = await import('../backup/backup-file');
    const manager = new BackupFileManager();

    return manager.parseBackupFile(qrData);
  }
}
