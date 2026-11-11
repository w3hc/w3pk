/**
 * Social Recovery Manager
 *
 * Splits encrypted wallet data among guardians using Shamir Secret Sharing.
 * Guardians can combine their shares to help recover the wallet.
 */

import type { BackupFile } from '../backup/types';
import { validateBackupFile } from '../backup/backup-file';
import { InvalidGuardianShareError } from '../core/errors';
import {
  splitSecret,
  combineShareSubsets,
  subsetCount,
  MAX_SHARE_SUBSETS,
  stringToBytes,
  bytesToString,
  bytesToHex,
  hexToBytes,
} from './shamir';
import { concatBytes } from '@noble/hashes/utils.js';

export interface GuardianShare {
  guardianId: string;
  guardianName: string;
  shareData: string; // Hex-encoded Shamir share
  shareIndex: number;
  threshold: number; // Number of shares required to recover (M in M-of-N)
  createdAt: string;
  walletAddress: string; // For verification
  splitId: string; // Hex, 16 random bytes shared by every share of one split
  checksum: string; // Hex, from guardianShareChecksum()
}

export const GUARDIAN_SHARE_VERSION = 2;

const SHARE_CHECKSUM_LABEL = 'w3pk-guardian-share-v2';

/**
 * SHA-256 of the label `w3pk-guardian-share-v2`, the split id, the share
 * index, the threshold, the lowercased wallet address, the guardian's name,
 * the creation date and the share bytes. The strings and byte fields are
 * length-prefixed (4 bytes big-endian), the index and threshold are one byte
 * each. It names a corrupted, edited or mislabelled share before the shares
 * are combined. It's no MAC: a guardian who recomputes it after editing the
 * share gets past it, and the backup's AES-GCM tag refuses the result.
 */
export async function guardianShareChecksum(
  share: Pick<
    GuardianShare,
    'splitId' | 'shareIndex' | 'threshold' | 'walletAddress' | 'guardianName' | 'createdAt' | 'shareData'
  >
): Promise<string> {
  const encoder = new TextEncoder();
  const prefixed = (value: Uint8Array) => {
    const length = new Uint8Array(4);
    new DataView(length.buffer).setUint32(0, value.length);
    return concatBytes(length, value);
  };
  const data = concatBytes(
    prefixed(encoder.encode(SHARE_CHECKSUM_LABEL)),
    prefixed(hexToBytes(share.splitId)),
    Uint8Array.of(share.shareIndex, share.threshold),
    prefixed(encoder.encode(share.walletAddress.toLowerCase())),
    prefixed(encoder.encode(share.guardianName)),
    prefixed(encoder.encode(share.createdAt)),
    prefixed(hexToBytes(share.shareData))
  );
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(data))));
}

const HEX = /^(?:[0-9a-f]{2})+$/i;
const SPLIT_ID = /^[0-9a-f]{32}$/i;

function isByte(value: unknown, min: number): value is number {
  return Number.isInteger(value) && (value as number) >= min && (value as number) <= 255;
}

async function checkShare(share: GuardianShare): Promise<void> {
  const fail = (reason: string): never => {
    throw new InvalidGuardianShareError(share.shareIndex, share.guardianName, reason);
  };
  if (
    typeof share.shareData !== 'string' ||
    !HEX.test(share.shareData) ||
    typeof share.splitId !== 'string' ||
    !SPLIT_ID.test(share.splitId) ||
    typeof share.checksum !== 'string' ||
    typeof share.walletAddress !== 'string' ||
    typeof share.guardianName !== 'string' ||
    typeof share.createdAt !== 'string' ||
    !isByte(share.shareIndex, 1) ||
    !isByte(share.threshold, 2)
  ) {
    fail('is malformed or uses an old format: ask the wallet owner to set up social recovery again');
  }
  if ((await guardianShareChecksum(share)) !== share.checksum.toLowerCase()) {
    fail("is corrupted or was edited: its checksum doesn't match");
  }
  const x = hexToBytes(share.shareData)[0];
  if (x !== share.shareIndex) {
    fail(`holds the x-coordinate ${x}, not its share index`);
  }
}

export interface SocialRecoverySetup {
  threshold: number; // M guardians needed
  totalShares: number; // N total guardians
  guardianShares: GuardianShare[];
  backupFile: BackupFile; // The encrypted wallet data (for reference)
  setupDate: string;
}

function shareFileFields(share: GuardianShare) {
  return {
    type: 'w3pk-guardian-share',
    version: GUARDIAN_SHARE_VERSION,
    guardianName: share.guardianName,
    walletAddress: share.walletAddress,
    shareData: share.shareData,
    shareIndex: share.shareIndex,
    threshold: share.threshold,
    createdAt: share.createdAt,
    splitId: share.splitId,
    checksum: share.checksum,
  };
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

    const splitId = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
    const createdAt = new Date().toISOString();
    const guardianShares: GuardianShare[] = await Promise.all(
      guardians.map(async (guardian, index) => {
        const share = {
          guardianId: crypto.randomUUID(),
          guardianName: guardian.name,
          shareData: bytesToHex(shares[index]),
          shareIndex: index + 1,
          threshold,
          createdAt,
          walletAddress,
          splitId,
        };
        return { ...share, checksum: await guardianShareChecksum(share) };
      })
    );

    return {
      threshold,
      totalShares: guardians.length,
      guardianShares,
      backupFile,
      setupDate: new Date().toISOString(),
    };
  }

  /**
   * Combine guardian shares to recover the encrypted wallet data: the backup
   * that most threshold-sized subsets of the shares rebuild
   *
   * @param shares - Array of guardian shares (must have at least threshold shares)
   * @throws InvalidGuardianShareError as rebuildBackups()
   */
  async recoverFromShares(shares: GuardianShare[]): Promise<BackupFile> {
    return (await this.rebuildBackups(shares)).backups[0];
  }

  /**
   * The distinct backups that threshold-sized subsets of the shares rebuild
   * (up to MAX_SHARE_SUBSETS subsets), the one most subsets agree on first.
   * When more shares than the threshold are given, a share whose checksum
   * fails is left out as long as the others reach the threshold.
   * `walletAddress` is the address the shares left in carry.
   *
   * @throws InvalidGuardianShareError naming a corrupted or edited share, one
   * from another split, a duplicate, or a share in an old format
   */
  async rebuildBackups(
    shares: GuardianShare[]
  ): Promise<{ backups: BackupFile[]; walletAddress: string }> {
    if (shares.length < 2) {
      throw new Error('At least 2 shares required for recovery');
    }

    const failures = await Promise.all(
      shares.map((share) => checkShare(share).then(() => undefined, (error: unknown) => error))
    );
    const valid = shares.filter((_, i) => failures[i] === undefined);
    const failure = failures.find((error) => error !== undefined);
    if (failure !== undefined && (valid.length < 2 || valid.length < valid[0].threshold)) {
      throw failure;
    }
    shares = valid;

    const splitCounts = new Map<string, number>();
    const splitOf = (share: GuardianShare) => share.splitId.toLowerCase();
    for (const share of shares) {
      splitCounts.set(splitOf(share), (splitCounts.get(splitOf(share)) ?? 0) + 1);
    }
    const splitId = [...splitCounts].reduce((best, entry) => (entry[1] > best[1] ? entry : best))[0];
    const reference = shares.find((share) => splitOf(share) === splitId)!;
    const stranger = shares.find((share) => splitOf(share) !== splitId);
    if (stranger) {
      throw new InvalidGuardianShareError(
        stranger.shareIndex,
        stranger.guardianName,
        `comes from another social recovery setup than share ${reference.shareIndex} (${reference.guardianName})`
      );
    }
    const seen = new Set<number>();
    for (const share of shares) {
      if (seen.has(share.shareIndex)) {
        throw new InvalidGuardianShareError(share.shareIndex, share.guardianName, 'is given twice');
      }
      seen.add(share.shareIndex);
    }

    const threshold = shares[0].threshold;
    const firstAddress = shares[0].walletAddress;

    if (shares.length < threshold) {
      throw new Error(
        `Need at least ${threshold} shares to recover, but only ${shares.length} provided`
      );
    }

    const allMatch = shares.every(
      share =>
        share.walletAddress.toLowerCase() === firstAddress.toLowerCase() &&
        share.threshold === threshold
    );

    if (!allMatch) {
      throw new Error('Shares are from different wallets or have inconsistent thresholds');
    }

    const shareBytes = shares.map(share => hexToBytes(share.shareData));
    const votes = new Map<string, { backup: BackupFile; count: number }>();
    let firstError: unknown;
    for (const secret of combineShareSubsets(shareBytes, threshold)) {
      const json = bytesToString(secret);
      const known = votes.get(json);
      if (known) {
        known.count++;
        continue;
      }
      try {
        let parsed: unknown;
        try {
          parsed = JSON.parse(json);
        } catch {
          throw new Error('Recovered data is not a backup file - corrupted shares');
        }
        votes.set(json, { backup: validateBackupFile(parsed), count: 1 });
      } catch (error) {
        if (firstError === undefined) firstError = error;
      }
    }

    if (votes.size === 0) {
      const tried = Math.min(subsetCount(shares.length, threshold), MAX_SHARE_SUBSETS);
      throw tried === 1
        ? firstError
        : new Error(
            `None of the ${tried} subsets of ${threshold} shares rebuilds a backup file: the shares are corrupted`
          );
    }
    return {
      backups: [...votes.values()].sort((a, b) => b.count - a.count).map(({ backup }) => backup),
      walletAddress: firstAddress,
    };
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
      ...shareFileFields(share),
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
Split ID: ${share.splitId}
Checksum: ${share.checksum}

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
   *
   * @throws InvalidGuardianShareError for a share in an old format
   */
  parseGuardianShare(shareJson: string): GuardianShare {
    const data = JSON.parse(shareJson);

    if (data.type !== 'w3pk-guardian-share') {
      throw new Error('Invalid guardian share format');
    }

    if (data.version !== GUARDIAN_SHARE_VERSION) {
      throw new InvalidGuardianShareError(
        data.shareIndex,
        data.guardianName,
        `uses format version ${String(data.version)}, which w3pk no longer reads: combine version 1 shares with w3pk v0.11.1, or ask the wallet owner to set up social recovery again`
      );
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
      splitId: data.splitId,
      checksum: data.checksum,
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
    const json = JSON.stringify(shareFileFields(share), null, 2);

    const blob = new Blob([json], { type: 'application/json' });
    const filename = `w3pk-guardian-${share.guardianName.replace(/\s+/g, '-')}-share-${share.shareIndex}.json`;

    return { blob, filename };
  }
}
