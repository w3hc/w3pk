/**
 * Social Recovery Manager
 *
 * Splits encrypted wallet data among guardians using Shamir Secret Sharing.
 * Guardians can combine their shares to help recover the wallet.
 */

import type { BackupFile } from '../backup/types';
import { validateBackupFile } from '../backup/backup-file';
import { UnsupportedBackupVersionError } from '../core/errors';
import {
  splitSecret,
  combineShares,
  stringToBytes,
  bytesToString,
  bytesToHex,
  hexToBytes,
} from './shamir';

export interface GuardianShare {
  guardianId: string;
  guardianName: string;
  shareData: string; // Hex-encoded Shamir share
  shareIndex: number;
  threshold: number; // Number of shares required to recover (M in M-of-N)
  createdAt: string;
  walletAddress: string; // For verification
}

export interface SocialRecoverySetup {
  threshold: number; // M guardians needed
  totalShares: number; // N total guardians
  guardianShares: GuardianShare[];
  backupFile: BackupFile; // The encrypted wallet data (for reference)
  setupDate: string;
}

export class SocialRecovery {
  /**
   * Split encrypted wallet among guardians using Shamir Secret Sharing
   *
   * @param backupFile - The encrypted wallet data to split
   * @param guardians - List of guardian names
   * @param threshold - Number of guardians required to recover (M-of-N)
   * @param walletAddress - Labels the shares; the backup file holds no address
   */
  async splitAmongGuardians(
    backupFile: BackupFile,
    guardians: Array<{ name: string; email?: string }>,
    threshold: number,
    walletAddress: string
  ): Promise<SocialRecoverySetup> {
    if (threshold > guardians.length) {
      throw new Error('Threshold cannot exceed number of guardians');
    }

    if (threshold < 2) {
      throw new Error('Threshold must be at least 2 for security');
    }

    if (guardians.length > 255) {
      throw new Error('Cannot have more than 255 guardians');
    }

    // Serialize the backup file to JSON
    const backupJson = JSON.stringify(backupFile);
    const secretBytes = stringToBytes(backupJson);

    // Split using Shamir Secret Sharing
    const shares = splitSecret(secretBytes, threshold, guardians.length);

    // Create guardian share objects
    const guardianShares: GuardianShare[] = guardians.map((guardian, index) => ({
      guardianId: crypto.randomUUID(),
      guardianName: guardian.name,
      shareData: bytesToHex(shares[index]),
      shareIndex: index + 1,
      threshold, // Store the original threshold in each share
      createdAt: new Date().toISOString(),
      walletAddress,
    }));

    return {
      threshold,
      totalShares: guardians.length,
      guardianShares,
      backupFile,
      setupDate: new Date().toISOString(),
    };
  }

  /**
   * Combine guardian shares to recover the encrypted wallet data
   *
   * @param shares - Array of guardian shares (must have at least threshold shares)
   */
  async recoverFromShares(shares: GuardianShare[]): Promise<BackupFile> {
    if (shares.length < 2) {
      throw new Error('At least 2 shares required for recovery');
    }

    // Extract threshold from first share
    const threshold = shares[0].threshold;
    const firstAddress = shares[0].walletAddress;

    if (!threshold) {
      throw new Error('Invalid share: missing threshold information');
    }

    if (shares.length < threshold) {
      throw new Error(
        `Need at least ${threshold} shares to recover, but only ${shares.length} provided`
      );
    }

    // Verify all shares are for the same wallet and have consistent threshold
    const allMatch = shares.every(
      share =>
        share.walletAddress === firstAddress &&
        share.threshold === threshold
    );

    if (!allMatch) {
      throw new Error('Shares are from different wallets or have inconsistent thresholds');
    }

    // Convert hex shares back to bytes
    const shareBytes = shares.map(share => hexToBytes(share.shareData));

    // Combine shares using Shamir with the original threshold
    const recoveredBytes = combineShares(shareBytes, threshold);

    // Convert back to string and parse JSON
    const backupJson = bytesToString(recoveredBytes);
    let recovered: unknown;
    try {
      recovered = JSON.parse(backupJson);
    } catch {
      throw new Error('Recovered data is not a backup file - corrupted shares');
    }

    try {
      return validateBackupFile(recovered);
    } catch (error) {
      if (error instanceof UnsupportedBackupVersionError) {
        error.backupFileJson = backupJson;
      }
      throw error;
    }
  }

  /**
   * Create guardian invitation with QR code
   * The guardian receives their share which they must keep safe
   */
  async createGuardianInvitation(
    share: GuardianShare,
    message?: string
  ): Promise<{
    qrCodeDataURL?: string;
    shareDocument: string;
    shareJson: string;
  }> {
    const invitation = {
      type: 'w3pk-guardian-share',
      version: 1,
      guardianName: share.guardianName,
      walletAddress: share.walletAddress,
      shareData: share.shareData,
      shareIndex: share.shareIndex,
      threshold: share.threshold,
      createdAt: share.createdAt,
      message: message || `You have been chosen as a recovery guardian for wallet ${share.walletAddress.substring(0, 10)}...`,
    };

    const shareJson = JSON.stringify(invitation, null, 2);

    // Generate QR code if qrcode package is available
    let qrCodeDataURL: string | undefined;
    try {
      const QRCode = await import('qrcode');
      qrCodeDataURL = await QRCode.toDataURL(shareJson, {
        errorCorrectionLevel: 'H',
        width: 512,
      });
    } catch (error) {
      // QR code is optional
      console.warn('QR code generation not available:', error);
    }

    // Create human-readable document
    const shareDocument = `
═══════════════════════════════════════════════════════════════
                    W3PK GUARDIAN RECOVERY SHARE
═══════════════════════════════════════════════════════════════

Guardian: ${share.guardianName}
Wallet Address: ${share.walletAddress}
Share Index: ${share.shareIndex}
Created: ${new Date(share.createdAt).toLocaleDateString()}

${message || `You have been chosen as a recovery guardian for this wallet.`}

IMPORTANT INSTRUCTIONS:
-----------------------

1. KEEP THIS SAFE
   This share is part of a social recovery system: the shares of any
   ${share.threshold} guardians combined recover the wallet.

2. NEVER SHARE THIS ALONE
   A single share cannot recover the wallet - it's secure to store.
   However, keep it confidential to maintain the owner's security.

3. WHEN NEEDED FOR RECOVERY
   The wallet owner will contact you and other guardians.
   You'll need to provide this share data for wallet recovery.

4. STORAGE RECOMMENDATIONS
   ✓ Save this file in a password manager
   ✓ Print and store in a safe place
   ✓ Save to encrypted cloud storage
   ✗ Do NOT email unencrypted
   ✗ Do NOT post publicly

SHARE DATA:
-----------
${share.shareData}

═══════════════════════════════════════════════════════════════
                Generated by w3pk - Web3 Passkey SDK
                      https://github.com/w3hc/w3pk
═══════════════════════════════════════════════════════════════
`;

    return {
      qrCodeDataURL,
      shareDocument,
      shareJson,
    };
  }

  /**
   * Parse guardian share from JSON
   */
  parseGuardianShare(shareJson: string): GuardianShare {
    const data = JSON.parse(shareJson);

    if (data.type !== 'w3pk-guardian-share') {
      throw new Error('Invalid guardian share format');
    }

    if (!data.threshold) {
      throw new Error('Invalid guardian share: missing threshold information');
    }

    return {
      guardianId: crypto.randomUUID(), // Generate new ID for this import
      guardianName: data.guardianName,
      shareData: data.shareData,
      shareIndex: data.shareIndex,
      threshold: data.threshold,
      createdAt: data.createdAt,
      walletAddress: data.walletAddress,
    };
  }

  /**
   * Verify that a set of shares can successfully recover wallet data
   * This is useful for testing the recovery process
   */
  async verifyRecovery(shares: GuardianShare[]): Promise<{
    canRecover: boolean;
    recoveredAddress?: string;
    error?: string;
  }> {
    try {
      await this.recoverFromShares(shares);

      return {
        canRecover: true,
        recoveredAddress: shares[0].walletAddress,
      };
    } catch (error) {
      return {
        canRecover: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Create downloadable share file for a guardian
   */
  createShareDownload(share: GuardianShare): {
    blob: Blob;
    filename: string;
  } {
    const json = JSON.stringify(
      {
        type: 'w3pk-guardian-share',
        version: 1,
        guardianName: share.guardianName,
        walletAddress: share.walletAddress,
        shareData: share.shareData,
        shareIndex: share.shareIndex,
        threshold: share.threshold,
        createdAt: share.createdAt,
      },
      null,
      2
    );

    const blob = new Blob([json], { type: 'application/json' });
    const filename = `w3pk-guardian-${share.guardianName.replace(/\s+/g, '-')}-share-${share.shareIndex}.json`;

    return { blob, filename };
  }
}
