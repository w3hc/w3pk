/**
 * BackupFile v3 Manager
 *
 * Creates a universal "floppy disk" backup file that can be used to:
 * 1. Restore wallet with existing passkey (same or synced device)
 * 2. Register new passkey with this wallet (fresh device)
 * 3. Sync wallet across devices
 * 4. Split among guardians for social recovery (via Shamir)
 */

import { BACKUP_FILE_VERSION } from './types';
import type { BackupCredential, BackupFile } from './types';
import {
  ARGON2ID_MAX_PARAMS,
  ARGON2ID_PARAMS,
  assertStrongPassword,
  deriveKeyFromPasswordArgon2id,
} from './encryption';
import { encryptData, decryptData } from '../wallet/crypto';
import {
  CryptoError,
  RemovedBackupMethodError,
  UnsupportedBackupVersionError,
} from '../core/errors';
import {
  arrayBufferToBase64Url,
  base64ToArrayBuffer,
  base64UrlToArrayBuffer,
} from '../utils/base64';

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

function invalid(reason: string): never {
  throw new Error(`Invalid backup file: ${reason}`);
}

function isBoundedInt(value: unknown, max: number): boolean {
  return Number.isInteger(value) && (value as number) >= 1 && (value as number) <= max;
}

function saltLength(salt: unknown): number {
  try {
    return typeof salt === 'string' ? base64ToArrayBuffer(salt).byteLength : 0;
  } catch {
    return 0;
  }
}

/**
 * Checks that `data` is a BackupFile v3 and returns it.
 * Throws RemovedBackupMethodError for a `passkey` or `hybrid` backup and
 * UnsupportedBackupVersionError for any other file that isn't v3.
 */
export function validateBackupFile(data: unknown): BackupFile {
  if (!data || typeof data !== 'object') invalid('not a JSON object');
  const file = data as Record<string, any>;

  if (REMOVED_BACKUP_METHODS.includes(file.encryptionMethod)) {
    throw new RemovedBackupMethodError(file.encryptionMethod);
  }
  if (file.version !== BACKUP_FILE_VERSION) {
    throw new UnsupportedBackupVersionError(file.version, file.encryptionMethod);
  }
  if (typeof file.createdAt !== 'string' || typeof file.encryptedMnemonic !== 'string') {
    invalid('missing required fields');
  }

  if (file.encryptionMethod === 'password') {
    const kdf = file.passwordEncryption;
    if (
      !kdf ||
      kdf.kdf !== 'argon2id' ||
      saltLength(kdf.salt) < 16 ||
      saltLength(kdf.salt) > 64 ||
      !isBoundedInt(kdf.memoryKiB, ARGON2ID_MAX_PARAMS.memoryKiB) ||
      !isBoundedInt(kdf.passes, ARGON2ID_MAX_PARAMS.passes) ||
      !isBoundedInt(kdf.parallelism, ARGON2ID_MAX_PARAMS.parallelism) ||
      kdf.memoryKiB < 8 * kdf.parallelism
    ) {
      invalid('password backup without valid Argon2id parameters');
    }
  } else if (file.encryptionMethod === 'prf') {
    if (!file.prfSalt || !file.credential?.id || !file.credential.publicKey) {
      invalid('PRF backup without its salt or passkey');
    }
  } else {
    invalid(`unknown encryption method ${file.encryptionMethod}`);
  }

  return file as BackupFile;
}

async function addressOf(mnemonic: string): Promise<string> {
  const { Wallet } = await import('ethers');
  try {
    return Wallet.fromPhrase(mnemonic).address;
  } catch (error) {
    throw new CryptoError('Decrypted backup is not a valid mnemonic', error);
  }
}

function toJson(backupFile: BackupFile): { backupFile: BackupFile; json: string; blob: Blob } {
  const json = JSON.stringify(backupFile, null, 2);
  return { backupFile, json, blob: new Blob([json], { type: 'application/json' }) };
}

export class BackupFileManager {
  /**
   * Create a BackupFile v3 encrypted with a password through Argon2id
   * This is the backup that restores without a passkey
   *
   * @param mnemonic - The BIP39 mnemonic to encrypt
   * @param password - User's password for encryption
   * @param credential - The passkey that owns the wallet, so a fresh device can sync with it
   * @param username - The wallet owner's username, restored with the passkey on a fresh device
   * @throws WeakPasswordError when validatePasswordStrength() refuses the password
   */
  async createPasswordBackup(
    mnemonic: string,
    password: string,
    credential?: BackupCredential,
    username?: string
  ): Promise<{ backupFile: BackupFile; json: string; blob: Blob }> {
    assertStrongPassword(password);

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKeyFromPasswordArgon2id(password, salt, ARGON2ID_PARAMS);

    return toJson({
      version: BACKUP_FILE_VERSION,
      createdAt: new Date().toISOString(),
      encryptedMnemonic: await encryptData(mnemonic, key),
      encryptionMethod: 'password',
      passwordEncryption: {
        kdf: 'argon2id',
        salt: btoa(String.fromCharCode(...salt)),
        ...ARGON2ID_PARAMS,
      },
      ...(credential && { credential: { id: credential.id, publicKey: credential.publicKey } }),
      ...(username && { username }),
    });
  }

  /**
   * Create a BackupFile v3 encrypted with a key derived from the passkey's
   * PRF output: decrypting needs a fresh assertion with that passkey, which
   * syncs within its platform ecosystem
   *
   * @param prfSalt - From generatePrfSalt()
   * @param prfOutput - PRF output of `credential` at prfSyncInput(prfSalt)
   */
  async createPrfBackup(
    mnemonic: string,
    credential: BackupCredential,
    username: string,
    prfSalt: string,
    prfOutput: BufferSource
  ): Promise<{ backupFile: BackupFile; json: string; blob: Blob }> {
    const encryptionKey = await derivePrfBackupKey(prfOutput, prfSalt);

    return toJson({
      version: BACKUP_FILE_VERSION,
      createdAt: new Date().toISOString(),
      encryptedMnemonic: await encryptData(mnemonic, encryptionKey),
      encryptionMethod: 'prf',
      credential: { id: credential.id, publicKey: credential.publicKey },
      prfSalt,
      username,
    });
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
    validateBackupFile(backupFile);
    if (backupFile.encryptionMethod !== 'prf' || !backupFile.prfSalt) {
      throw new Error('This backup is not a PRF backup.');
    }

    const encryptionKey = await derivePrfBackupKey(prfOutput, backupFile.prfSalt);
    const mnemonic = await decryptData(backupFile.encryptedMnemonic, encryptionKey);

    return { mnemonic, ethereumAddress: await addressOf(mnemonic) };
  }

  /**
   * Restore from a password backup
   * Use case: User doesn't have passkey on this device yet
   *
   * @throws CryptoError on a wrong password or a corrupted file
   */
  async restoreWithPassword(
    backupFile: BackupFile,
    password: string
  ): Promise<{ mnemonic: string; ethereumAddress: string }> {
    validateBackupFile(backupFile);
    const kdf = backupFile.passwordEncryption;
    if (backupFile.encryptionMethod !== 'password' || !kdf) {
      throw new Error('This backup is not password-protected.');
    }

    const salt = new Uint8Array(base64ToArrayBuffer(kdf.salt));
    const key = await deriveKeyFromPasswordArgon2id(password, salt, kdf);
    let mnemonic: string;
    try {
      mnemonic = await decryptData(backupFile.encryptedMnemonic, key);
    } catch (error) {
      throw new CryptoError('Wrong password or corrupted backup', error);
    }

    return { mnemonic, ethereumAddress: await addressOf(mnemonic) };
  }

  /**
   * Parse a BackupFile v3 from JSON string or Blob
   *
   * @throws UnsupportedBackupVersionError for a file that isn't v3
   * @throws RemovedBackupMethodError for a `passkey` or `hybrid` backup
   */
  async parseBackupFile(data: string | Blob): Promise<BackupFile> {
    const json = data instanceof Blob ? await data.text() : data;
    return validateBackupFile(JSON.parse(json));
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
    const defaultFilename = `w3pk-backup-${new Date().toISOString().split('T')[0]}.json`;

    return {
      blob,
      filename: filename || defaultFilename,
    };
  }
}
