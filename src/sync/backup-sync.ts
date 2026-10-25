/**
 * Cross-Device Sync Manager
 *
 * Syncs wallets across devices where passkey is already synced.
 * Use case: User has passkey on mobile and desktop, but wallet only on desktop.
 * They can export wallet data from desktop and import on mobile.
 */

import type { BackupCredential, BackupFile } from '../backup/types';

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
   * Runs a fresh assertion with the passkey and encrypts with a key derived
   * from its PRF output, so any device where the passkey synced can decrypt
   * it without a password. Without PRF support, falls back to a password
   * backup when `password` is given.
   *
   * @throws PrfUnsupportedError when PRF is unavailable and no password is given
   * @throws AuthenticationError when the assertion fails or is cancelled
   */
  async exportForSync(
    mnemonic: string,
    ethereumAddress: string,
    credential: BackupCredential,
    username: string,
    password?: string
  ): Promise<{ backupFile: BackupFile; json: string; blob: Blob }> {
    const { BackupFileManager, generatePrfSalt, prfSyncInput } = await import('../backup/backup-file');
    const { evaluatePrf } = await import('../auth/prf');
    const { PrfUnsupportedError } = await import('../core/errors');
    const manager = new BackupFileManager();

    const prfSalt = generatePrfSalt();
    let output: ArrayBuffer;
    try {
      ({ output } = await evaluatePrf(await prfSyncInput(prfSalt), credential.id));
    } catch (error) {
      if (error instanceof PrfUnsupportedError && password) {
        return manager.createPasswordBackup(mnemonic, ethereumAddress, password, credential);
      }
      throw error;
    }

    try {
      return await manager.createPrfBackup(
        mnemonic,
        ethereumAddress,
        credential,
        username,
        prfSalt,
        output
      );
    } finally {
      new Uint8Array(output).fill(0);
    }
  }

  /**
   * Import a PRF backup from another device
   * Runs one assertion restricted to the backup's passkey, checks its
   * signature against `publicKey`, then decrypts with the PRF output
   *
   * @param publicKey - The passkey's public key: this device's, or the backup's on a fresh device
   * @throws SyncBootstrapError ('PUBLIC_KEY_MISMATCH') when the signature doesn't match `publicKey`
   */
  async importFromSync(
    backupFile: BackupFile,
    publicKey: string
  ): Promise<{ mnemonic: string; ethereumAddress: string }> {
    const { BackupFileManager, prfSyncInput } = await import('../backup/backup-file');
    const { evaluatePrf } = await import('../auth/prf');
    const { verifyAssertionSignature } = await import('../auth/authenticate');
    const { SyncBootstrapError } = await import('../core/errors');
    const manager = new BackupFileManager();

    if (backupFile.encryptionMethod !== 'prf' || !backupFile.prfSalt || !backupFile.credential) {
      throw new Error('This backup is not a PRF backup.');
    }
    const credentialId = backupFile.credential.id;

    const evaluation = await evaluatePrf(await prfSyncInput(backupFile.prfSalt), credentialId);
    let result: { mnemonic: string; ethereumAddress: string };
    try {
      if (evaluation.credentialId !== credentialId) {
        throw new SyncBootstrapError('CREDENTIAL_MISMATCH', evaluation.credentialId);
      }
      if (!(await verifyAssertionSignature(evaluation.assertion, publicKey))) {
        throw new SyncBootstrapError('PUBLIC_KEY_MISMATCH', credentialId);
      }
      result = await manager.restoreWithPrf(backupFile, evaluation.output);
    } finally {
      new Uint8Array(evaluation.output).fill(0);
    }

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
