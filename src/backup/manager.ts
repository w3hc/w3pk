/**
 * Main Backup Manager
 * Orchestrates all backup and recovery operations
 */

import type {
  BackupStatus,
  SecurityScore,
  EncryptedBackupInfo,
  SocialRecoveryStatus,
} from './types';
import { PASSKEY_INDEPENDENT_METHODS } from './types';
import { BackupStorage } from './storage';
import { detectEvictionRisk } from '../utils/eviction';

export class BackupManager {
  private storage: BackupStorage;
  private verificationStorageKey = 'w3pk_backup_verifications';

  constructor() {
    this.storage = new BackupStorage();
  }

  /**
   * Get comprehensive backup status
   * Shows user exactly what protects their wallet
   */
  async getBackupStatus(ethereumAddress: string): Promise<BackupStatus> {
    // Get all backups for this address
    const backups = await this.storage.getBackupsByAddress(ethereumAddress);

    // Detect passkey sync capabilities
    const passkeySync = await this.detectPasskeySync();

    const methods = [...new Set(backups.map((b) => b.method))];
    const lastBackupAt = backups
      .map((b) => b.createdAt)
      .sort()
      .pop();

    // Get encrypted backup info
    const encryptedBackups: EncryptedBackupInfo[] = backups
      .filter((backup) => backup.method !== 'phrase')
      .map((backup) => ({
        id: backup.id,
        method: backup.method as EncryptedBackupInfo['method'],
        location: 'local', // Could be enhanced to track cloud storage
        createdAt: backup.createdAt,
        deviceFingerprint: backup.deviceFingerprint,
      }));

    // Get verification status
    const verificationStatus = this.getVerificationStatus(ethereumAddress);

    const hasBackup = methods.some((m) => PASSKEY_INDEPENDENT_METHODS.includes(m));
    const recommendedMode = !hasBackup
      ? 'password'
      : methods.includes('prf')
        ? undefined
        : 'prf';

    // Build status
    const status: BackupStatus = {
      hasBackup,
      ...(recommendedMode && { recommendedMode }),
      evictionRisk: await detectEvictionRisk(),
      lastBackupAt,
      methods,
      passkeySync,
      recoveryPhrase: {
        verified: verificationStatus.verified,
        verificationCount: verificationStatus.count,
        encryptedBackups,
      },
      securityScore: this.calculateSecurityScore(
        passkeySync,
        encryptedBackups,
        undefined,
        verificationStatus,
        hasBackup
      ),
    };

    return status;
  }

  /**
   * Detect passkey sync capabilities
   */
  private async detectPasskeySync() {
    // Return default values in non-browser environments
    if (typeof navigator === 'undefined') {
      return {
        enabled: false,
        deviceCount: 0,
        lastSyncTime: undefined,
        platform: 'unknown' as const,
      };
    }

    // Detect platform
    const userAgent = navigator.userAgent.toLowerCase();
    let platform: 'apple' | 'google' | 'microsoft' | 'unknown' = 'unknown';

    if (userAgent.includes('mac') || userAgent.includes('iphone') || userAgent.includes('ipad')) {
      platform = 'apple';
    } else if (userAgent.includes('android')) {
      platform = 'google';
    } else if (userAgent.includes('windows')) {
      platform = 'microsoft';
    }

    // Check if WebAuthn supports resident credentials (required for sync)
    const supportsResidentKeys = await this.checkResidentKeySupport();

    // Estimate device count (simplified - in production, track via server)
    const deviceCount = 1; // Current device

    return {
      enabled: supportsResidentKeys,
      deviceCount,
      lastSyncTime: supportsResidentKeys ? new Date().toISOString() : undefined,
      platform,
    };
  }

  /**
   * Check if platform supports resident keys (required for passkey sync)
   */
  private async checkResidentKeySupport(): Promise<boolean> {
    if (typeof window === 'undefined' || !window.PublicKeyCredential) {
      return false;
    }

    try {
      // Check if platform authenticator is available
      const available =
        await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      return available;
    } catch {
      return false;
    }
  }

  /**
   * Get verification status from storage
   */
  private getVerificationStatus(ethereumAddress: string): {
    verified: boolean;
    count: number;
  } {
    try {
      const stored =
        typeof localStorage !== 'undefined'
          ? localStorage.getItem(this.verificationStorageKey)
          : null;

      if (!stored) {
        return { verified: false, count: 0 };
      }

      const verifications = JSON.parse(stored);
      const addressVerifications = verifications[ethereumAddress.toLowerCase()] || {
        verified: false,
        count: 0,
      };

      return addressVerifications;
    } catch {
      return { verified: false, count: 0 };
    }
  }

  async hasBackup(ethereumAddress: string): Promise<boolean> {
    const backups = await this.storage.getBackupsByAddress(ethereumAddress);
    return backups.some((b) => PASSKEY_INDEPENDENT_METHODS.includes(b.method));
  }

  /**
   * Record that the user confirmed writing down their recovery phrase
   */
  async confirmRecoveryPhraseBackup(
    ethereumAddress: string,
    addressChecksum: string
  ): Promise<void> {
    await this.storage.storeBackupMetadata({
      id: crypto.randomUUID(),
      ethereumAddress,
      method: 'phrase',
      createdAt: new Date().toISOString(),
      addressChecksum,
    });
  }

  /**
   * Mark backup as verified (called after successful restore)
   */
  markBackupVerified(ethereumAddress: string): void {
    try {
      const stored =
        typeof localStorage !== 'undefined'
          ? localStorage.getItem(this.verificationStorageKey)
          : null;

      const verifications = stored ? JSON.parse(stored) : {};
      const addressKey = ethereumAddress.toLowerCase();

      if (!verifications[addressKey]) {
        verifications[addressKey] = { verified: false, count: 0 };
      }

      verifications[addressKey].verified = true;
      verifications[addressKey].count += 1;
      verifications[addressKey].lastVerifiedAt = new Date().toISOString();

      if (typeof localStorage !== 'undefined') {
        localStorage.setItem(this.verificationStorageKey, JSON.stringify(verifications));
      }
    } catch (error) {
      console.error('Failed to mark backup as verified:', error);
    }
  }

  /**
   * Calculate security score
   */
  private calculateSecurityScore(
    passkeySync: any,
    encryptedBackups: EncryptedBackupInfo[],
    socialRecoveryStatus?: SocialRecoveryStatus,
    verificationStatus?: { verified: boolean; count: number },
    restoresWithoutPasskey = false
  ): SecurityScore {
    // Calculate social recovery score
    let socialRecoveryScore = 0;
    if (socialRecoveryStatus?.enabled) {
      // Base score for having social recovery setup
      socialRecoveryScore = 20;

      // Bonus for verified guardians
      if (socialRecoveryStatus.verifiedGuardians >= socialRecoveryStatus.threshold) {
        socialRecoveryScore += 10; // +10 if enough guardians are verified
      }
    }

    // Calculate verification score
    let verificationScore = 0;
    if (verificationStatus?.verified) {
      verificationScore = 10; // 10 points for verifying backup
      // Bonus for multiple verifications (up to 10 more points)
      verificationScore += Math.min(verificationStatus.count - 1, 10);
    }

    const breakdown = {
      passkeyActive: passkeySync.enabled ? 20 : 0,
      passkeyMultiDevice: passkeySync.deviceCount > 1 ? 10 : 0,
      phraseVerified: verificationScore,
      encryptedBackup: encryptedBackups.length > 0 ? 20 : 0,
      socialRecovery: socialRecoveryScore,
    };

    const sum = Object.values(breakdown).reduce((acc, val) => acc + val, 0);
    // Without a backup that restores without a passkey, losing this device
    // (or its storage) with no synced passkey loses the wallet for good
    const total = restoresWithoutPasskey ? sum : Math.min(sum, 20);

    let level: SecurityScore['level'];
    let nextMilestone: string;

    if (!restoresWithoutPasskey) {
      level = 'vulnerable';
      nextMilestone =
        'Create a password backup file or confirm your recovery phrase: without a backup that restores without a passkey, losing this device can lose the wallet';
    } else if (total <= 20) {
      level = 'vulnerable';
      nextMilestone = 'Create encrypted backup to reach "protected" (40+ pts)';
    } else if (total <= 50) {
      level = 'protected';
      nextMilestone = 'Set up social recovery to reach "secured" (70+ pts)';
    } else if (total <= 80) {
      level = 'secured';
      nextMilestone = 'Enable all methods to reach "fort-knox" (100 pts)';
    } else {
      level = 'fort-knox';
      nextMilestone = 'Maximum security achieved!';
    }

    return {
      total,
      breakdown,
      level,
      nextMilestone,
    };
  }
}
