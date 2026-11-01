/**
 * Simplified Backup File Manager
 *
 * Creates a universal "floppy disk" backup file that can be used to:
 * 1. Restore wallet with existing passkey (same or synced device)
 * 2. Register new passkey with this wallet (fresh device)
 * 3. Sync wallet across devices
 * 4. Split among guardians for social recovery (via Shamir)
 */

import type { BackupCredential, BackupFile } from './types';
import {
  encryptWithPassword,
  decryptWithPassword,
  deriveAddressChecksum,
} from './encryption';
import { encryptData, decryptData } from '../wallet/crypto';
import { CryptoError, RemovedBackupMethodError } from '../core/errors';
import { arrayBufferToBase64Url, base64UrlToArrayBuffer } from '../utils/base64';

const PRF_SYNC_LABEL = new TextEncoder().encode('w3pk-prf-sync-v1');

/** Random per-backup salt for a PRF backup, base64url */
export function generatePrfSalt(): string {
  return arrayBufferToBase64Url(crypto.getRandomValues(new Uint8Array(32)).buffer);
}

/** PRF input for a PRF backup: SHA-256("w3pk-prf-sync-v1" || prfSalt) */
export async function prfSyncInput(prfSalt: string): Promise<ArrayBuffer> {
  const salt = new Uint8Array(base64UrlToArrayBuffer(prfSalt));
  return crypto.subtle.digest('SHA-256', new Uint8Array([...PRF_SYNC_LABEL, ...salt]));
}

async function derivePrfBackupKey(prfOutput: BufferSource, prfSalt: string): Promise<CryptoKey> {
  try {
    const keyMaterial = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
    return await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: base64UrlToArrayBuffer(prfSalt),
        info: PRF_SYNC_LABEL,
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  } catch (error) {
    throw new CryptoError('Failed to derive backup key from PRF output', error);
  }
}

const REMOVED_BACKUP_METHODS = ['passkey', 'hybrid'];

/**
 * Throws RemovedBackupMethodError for a `passkey` or `hybrid` backup, and
 * rejects any other method but `password` and `prf`
 */
export function assertSupportedBackupMethod(backupFile: BackupFile): void {
  const method: string = backupFile.encryptionMethod;
  if (REMOVED_BACKUP_METHODS.includes(method)) {
    throw new RemovedBackupMethodError(method);
  }
  if (method !== 'password' && method !== 'prf') {
    throw new Error(`Invalid backup file: unknown encryption method ${method}`);
  }
}

export class BackupFileManager {
  /**
   * Create backup file encrypted with password
   * This is the primary method for creating portable backups
   *
   * @param mnemonic - The BIP39 mnemonic to encrypt
   * @param ethereumAddress - The Ethereum address for verification
   * @param password - User's password for encryption (required for security)
   * @param credential - The passkey that owns the wallet, so a fresh device can sync with it
   */
  async createPasswordBackup(
    mnemonic: string,
    ethereumAddress: string,
    password: string,
    credential?: BackupCredential
  ): Promise<{ backupFile: BackupFile; json: string; blob: Blob }> {
    if (!password || password.length < 1) {
      throw new Error('Password is required for password-based backup');
    }

    const salt = crypto.getRandomValues(new Uint8Array(32));
    const encrypted = await encryptWithPassword(mnemonic, password, salt);
    const addressChecksum = await deriveAddressChecksum(ethereumAddress);

    const backupFile: BackupFile = {
      createdAt: new Date().toISOString(),
      ethereumAddress,
      encryptedMnemonic: encrypted.encrypted,
      encryptionMethod: 'password',
      passwordEncryption: {
        salt: encrypted.salt,
        iv: encrypted.iv,
        iterations: encrypted.iterations,
      },
      ...(credential && { credential: { id: credential.id, publicKey: credential.publicKey } }),
      addressChecksum,
    };

    const json = JSON.stringify(backupFile, null, 2);
    const blob = new Blob([json], { type: 'application/json' });

    return { backupFile, json, blob };
  }

  /**
   * Create backup file encrypted with a key derived from the passkey's PRF
   * output: decrypting needs a fresh assertion with that passkey, which
   * syncs within its platform ecosystem
   *
   * @param prfSalt - From generatePrfSalt()
   * @param prfOutput - PRF output of `credential` at prfSyncInput(prfSalt)
   */
  async createPrfBackup(
    mnemonic: string,
    ethereumAddress: string,
    credential: BackupCredential,
    username: string,
    prfSalt: string,
    prfOutput: BufferSource
  ): Promise<{ backupFile: BackupFile; json: string; blob: Blob }> {
    const encryptionKey = await derivePrfBackupKey(prfOutput, prfSalt);
    const encryptedMnemonic = await encryptData(mnemonic, encryptionKey);
    const addressChecksum = await deriveAddressChecksum(ethereumAddress);

    const backupFile: BackupFile = {
      createdAt: new Date().toISOString(),
      ethereumAddress,
      encryptedMnemonic,
      encryptionMethod: 'prf',
      credential: { id: credential.id, publicKey: credential.publicKey },
      prfSalt,
      username,
      addressChecksum,
    };

    const json = JSON.stringify(backupFile, null, 2);
    const blob = new Blob([json], { type: 'application/json' });

    return { backupFile, json, blob };
  }

  /**
   * Restore from a PRF backup
   *
   * @param prfOutput - PRF output of the backup's passkey at prfSyncInput(backupFile.prfSalt)
   */
  async restoreWithPrf(
    backupFile: BackupFile,
    prfOutput: BufferSource
  ): Promise<{ mnemonic: string; ethereumAddress: string }> {
    if (backupFile.encryptionMethod !== 'prf' || !backupFile.prfSalt) {
      throw new Error('This backup is not a PRF backup.');
    }

    const encryptionKey = await derivePrfBackupKey(prfOutput, backupFile.prfSalt);
    const mnemonic = await decryptData(backupFile.encryptedMnemonic, encryptionKey);

    const { Wallet } = await import('ethers');
    const wallet = Wallet.fromPhrase(mnemonic);
    const addressChecksum = await deriveAddressChecksum(wallet.address);

    if (
      addressChecksum !== backupFile.addressChecksum ||
      wallet.address.toLowerCase() !== backupFile.ethereumAddress.toLowerCase()
    ) {
      throw new Error(
        'Address checksum mismatch - corrupted backup or decryption failure'
      );
    }

    return { mnemonic, ethereumAddress: wallet.address };
  }

  /**
   * Restore from backup file using password
   * Use case: User doesn't have passkey on this device yet
   */
  async restoreWithPassword(
    backupFile: BackupFile,
    password: string
  ): Promise<{ mnemonic: string; ethereumAddress: string }> {
    if (backupFile.encryptionMethod !== 'password' || !backupFile.passwordEncryption) {
      throw new Error('This backup is not password-protected.');
    }

    const mnemonic = await decryptWithPassword(
      backupFile.encryptedMnemonic,
      password,
      backupFile.passwordEncryption.salt,
      backupFile.passwordEncryption.iv,
      backupFile.passwordEncryption.iterations
    );

    // Verify address checksum
    const { Wallet } = await import('ethers');
    const wallet = Wallet.fromPhrase(mnemonic);
    const addressChecksum = await deriveAddressChecksum(wallet.address);

    if (addressChecksum !== backupFile.addressChecksum) {
      throw new Error(
        'Address checksum mismatch - corrupted backup or wrong password'
      );
    }

    return {
      mnemonic,
      ethereumAddress: backupFile.ethereumAddress,
    };
  }

  /**
   * Parse backup file from JSON string or Blob
   */
  async parseBackupFile(data: string | Blob): Promise<BackupFile> {
    let json: string;

    if (data instanceof Blob) {
      json = await data.text();
    } else {
      json = data;
    }

    const backupFile = JSON.parse(json) as BackupFile;

    // Validate required fields
    if (!backupFile.createdAt || !backupFile.ethereumAddress || !backupFile.encryptedMnemonic) {
      throw new Error('Invalid backup file: missing required fields');
    }
    assertSupportedBackupMethod(backupFile);
    if (
      backupFile.encryptionMethod === 'prf' &&
      (!backupFile.prfSalt || !backupFile.credential?.id || !backupFile.credential.publicKey)
    ) {
      throw new Error('Invalid backup file: PRF backup without its salt or passkey');
    }

    return backupFile;
  }

  /**
   * Export backup file as downloadable blob
   */
  createDownloadableBackup(
    backupFile: BackupFile,
    filename?: string
  ): { blob: Blob; filename: string } {
    const json = JSON.stringify(backupFile, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const defaultFilename = `w3pk-backup-${backupFile.ethereumAddress.substring(0, 8)}-${
      new Date().toISOString().split('T')[0]
    }.json`;

    return {
      blob,
      filename: filename || defaultFilename,
    };
  }
}
