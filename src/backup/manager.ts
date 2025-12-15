/**
 * Main Backup Manager
 * Orchestrates all backup and recovery operations
 */

import type {
  BackupStatus,
  SecurityScore,
  QRBackupOptions,
  RecoveryScenario,
  SimulationResult,
  BackupMetadata,
  EncryptedBackupInfo,
  SocialRecoveryStatus,
} from './types';
import { BackupStorage } from './storage';
import { QRBackupCreator } from './qr-backup';
import { SocialRecoveryManager } from '../recovery/social';

export class BackupManager {
  private storage: BackupStorage;
  private qrCreator: QRBackupCreator;
  private socialRecoveryManager: SocialRecoveryManager;
  private verificationStorageKey = 'w3pk_backup_verifications';

  constructor() {
    this.storage = new BackupStorage();
    this.qrCreator = new QRBackupCreator();
    this.socialRecoveryManager = new SocialRecoveryManager();
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

    // Get encrypted backup info
    const encryptedBackups: EncryptedBackupInfo[] = backups.map((backup) => ({
      id: backup.id,
      method: backup.method,
      location: 'local', // Could be enhanced to track cloud storage
      createdAt: backup.createdAt,
      deviceFingerprint: backup.deviceFingerprint,
    }));

    // Get social recovery status
    const socialRecoveryStatus = this.getSocialRecoveryStatus();

    // Get verification status
    const verificationStatus = this.getVerificationStatus(ethereumAddress);

    // Build status
    const status: BackupStatus = {
      passkeySync,
      recoveryPhrase: {
        verified: verificationStatus.verified,
        verificationCount: verificationStatus.count,
        encryptedBackups,
      },
      socialRecovery: socialRecoveryStatus,
      securityScore: this.calculateSecurityScore(
        passkeySync,
        encryptedBackups,
        socialRecoveryStatus,
        verificationStatus
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
   * Get social recovery status from SocialRecoveryManager
   */
  private getSocialRecoveryStatus(): SocialRecoveryStatus | undefined {
    const config = this.socialRecoveryManager.getSocialRecoveryConfig();
    if (!config) {
      return undefined;
    }

    const verifiedGuardians = config.guardians.filter((g) => g.status === 'active').length;

    return {
      enabled: true,
      guardians: config.guardians,
      threshold: config.threshold,
      sharesDistributed: config.guardians.length,
      verifiedGuardians,
    };
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
    verificationStatus?: { verified: boolean; count: number }
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

    const total = Object.values(breakdown).reduce((sum, val) => sum + val, 0);

    let level: SecurityScore['level'];
    let nextMilestone: string;

    if (total <= 20) {
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

  /**
   * Create QR code backup
   */
  async createQRBackup(
    mnemonic: string,
    ethereumAddress: string,
    options?: QRBackupOptions
  ): Promise<{
    qrCodeDataURL: string;
    instructions: string;
  }> {
    const { qrCodeDataURL, rawData, instructions } =
      await this.qrCreator.createQRBackup(mnemonic, ethereumAddress, options);

    // Store metadata
    const metadata: BackupMetadata = {
      id: crypto.randomUUID(),
      ethereumAddress,
      method: 'qr',
      createdAt: new Date().toISOString(),
      addressChecksum: JSON.parse(rawData).checksum,
    };

    await this.storage.storeBackupMetadata(metadata);

    return { qrCodeDataURL, instructions };
  }

  /**
   * Restore from QR backup
   */
  async restoreFromQR(
    qrData: string,
    password?: string
  ): Promise<{ mnemonic: string; ethereumAddress: string }> {
    return await this.qrCreator.restoreFromQR(qrData, password);
  }

  /**
   * Simulate recovery scenario (educational)
   */
  async simulateRecoveryScenario(
    scenario: RecoveryScenario,
    currentStatus: BackupStatus
  ): Promise<SimulationResult> {
    const methods: any[] = [];

    // Check available recovery methods based on scenario
    switch (scenario.type) {
      case 'lost-device':
        if (currentStatus.passkeySync.enabled && currentStatus.passkeySync.deviceCount > 1) {
          methods.push({
            method: 'Passkey Sync (iCloud/Google)',
            success: true,
            time: '5 minutes',
            requirements: ['Sign in to cloud account', 'Authenticate on new device'],
          });
        }

        if (currentStatus.recoveryPhrase.encryptedBackups.length > 0) {
          methods.push({
            method: 'Encrypted Backup',
            success: true,
            time: '2 minutes',
            requirements: ['Backup file', 'Password'],
          });
        }

        if (currentStatus.socialRecovery?.enabled) {
          methods.push({
            method: 'Social Recovery',
            success: true,
            time: '24 hours',
            requirements: [`${currentStatus.socialRecovery.threshold} guardian shares`],
          });
        }
        break;

      case 'lost-phrase':
        if (currentStatus.passkeySync.enabled) {
          methods.push({
            method: 'Passkey (current device)',
            success: true,
            time: 'instant',
            requirements: ['Current device', 'Biometric/PIN'],
          });
        }

        if (currentStatus.socialRecovery?.enabled) {
          methods.push({
            method: 'Social Recovery',
            success: true,
            time: '24 hours',
            requirements: [`${currentStatus.socialRecovery.threshold} guardian shares`],
          });
        }
        break;

      case 'lost-both':
        if (currentStatus.passkeySync.enabled && currentStatus.passkeySync.deviceCount > 1) {
          methods.push({
            method: 'Passkey Sync',
            success: true,
            time: '5 minutes',
            requirements: ['Cloud account access', 'New device'],
          });
        }

        if (currentStatus.socialRecovery?.enabled) {
          methods.push({
            method: 'Social Recovery',
            success: true,
            time: '24 hours',
            requirements: [`${currentStatus.socialRecovery.threshold} guardian shares`],
          });
        }
        break;

      case 'switch-platform':
        if (currentStatus.recoveryPhrase.encryptedBackups.length > 0) {
          methods.push({
            method: 'Encrypted Backup',
            success: true,
            time: '2 minutes',
            requirements: ['Backup file', 'Password'],
          });
        }

        if (currentStatus.socialRecovery?.enabled) {
          methods.push({
            method: 'Social Recovery',
            success: true,
            time: '24 hours',
            requirements: [`${currentStatus.socialRecovery.threshold} guardian shares`],
          });
        }
        break;
    }

    const success = methods.length > 0 && methods.some((m) => m.success);

    let educationalNote = '';
    if (success) {
      educationalNote = `✅ You're safe! ${methods.length} way${methods.length > 1 ? 's' : ''} to recover.\n\n`;
      educationalNote += 'Available recovery methods:\n';
      methods.forEach((m) => {
        educationalNote += `- ${m.method} (~${m.time})\n`;
      });
    } else {
      educationalNote = `❌ Wallet cannot be recovered in this scenario.\n\n`;
      educationalNote += 'Recommendation: Set up at least 2 backup methods to prevent total loss.';
    }

    return {
      scenario,
      success,
      availableMethods: methods,
      timeEstimate: success ? methods[0].time : 'N/A',
      educationalNote,
    };
  }
}
