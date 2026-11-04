/**
 * BackupFile v4 Manager
 *
 * Creates a universal "floppy disk" backup file that can be used to:
 * 1. Restore wallet with existing passkey (same or synced device)
 * 2. Register new passkey with this wallet (fresh device)
 * 3. Sync wallet across devices
 * 4. Split among guardians for social recovery (via Shamir)
 */

import { concatBytes } from '@noble/hashes/utils.js';
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

const BACKUP_AAD_LABEL = 'w3pk-backup-v4';

type BackupMetadata = Omit<BackupFile, 'encryptedMnemonic'>;

const FILE_FIELDS = [
  'version',
  'createdAt',
  'encryptedMnemonic',
  'encryptionMethod',
  'passwordEncryption',
  'credential',
  'prfSalt',
  'username',
];
const PASSWORD_ENCRYPTION_FIELDS = ['kdf', 'salt', 'memoryKiB', 'passes', 'parallelism'];
const CREDENTIAL_FIELDS = ['id', 'publicKey'];

/**
 * AES-GCM additional data of a BackupFile v4: the label `w3pk-backup-v4`
 * then every field but `encryptedMnemonic`, in a fixed order. An absent
 * field is 0x00; a string is 0x01, its UTF-8 length as 4 bytes big-endian,
 * then its bytes; an integer is 0x01 then 4 bytes big-endian.
 */
export function backupAdditionalData(file: BackupMetadata): Uint8Array<ArrayBuffer> {
  const parts: Uint8Array[] = [];
  const u32 = (value: number) => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value);
    return bytes;
  };
  const str = (value: string | undefined) => {
    if (value === undefined) return void parts.push(Uint8Array.of(0));
    const bytes = new TextEncoder().encode(value);
    parts.push(Uint8Array.of(1), u32(bytes.length), bytes);
  };
  const int = (value: number | undefined) => {
    if (value === undefined) return void parts.push(Uint8Array.of(0));
    parts.push(Uint8Array.of(1), u32(value));
  };
  const kdf = file.passwordEncryption;

  str(BACKUP_AAD_LABEL);
  int(file.version);
  str(file.createdAt);
  str(file.encryptionMethod);
  str(kdf?.kdf);
  str(kdf?.salt);
  int(kdf?.memoryKiB);
  int(kdf?.passes);
  int(kdf?.parallelism);
  str(file.credential?.id);
  str(file.credential?.publicKey);
  str(file.prfSalt);
  str(file.username);

  return new Uint8Array(concatBytes(...parts));
}

async function sealBackup(
  mnemonic: string,
  key: CryptoKey,
  metadata: BackupMetadata
): Promise<BackupFile> {
  const encryptedMnemonic = await encryptData(mnemonic, key, backupAdditionalData(metadata));
  return { ...metadata, encryptedMnemonic };
}

function hasOnly(value: object, fields: string[]): boolean {
  return Object.keys(value).every((field) => fields.includes(field));
}

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
 * Checks that `data` is a BackupFile v4 and returns it.
 * Throws RemovedBackupMethodError for a `passkey` or `hybrid` backup and
 * UnsupportedBackupVersionError for any other file that isn't v4.
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
  if (!hasOnly(file, FILE_FIELDS)) invalid('unknown fields');
  if (file.username !== undefined && typeof file.username !== 'string') invalid('username is not a string');
  if (file.prfSalt !== undefined && typeof file.prfSalt !== 'string') invalid('prfSalt is not a string');
  if (
    file.credential !== undefined &&
    (!file.credential ||
      typeof file.credential !== 'object' ||
      typeof file.credential.id !== 'string' ||
      typeof file.credential.publicKey !== 'string' ||
      !hasOnly(file.credential, CREDENTIAL_FIELDS))
  ) {
    invalid('credential is not { id, publicKey }');
  }

  if (file.encryptionMethod === 'password') {
    const kdf = file.passwordEncryption;
    if (
      !kdf ||
      typeof kdf !== 'object' ||
      !hasOnly(kdf, PASSWORD_ENCRYPTION_FIELDS) ||
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
    if (file.prfSalt !== undefined) invalid('password backup with a PRF salt');
  } else if (file.encryptionMethod === 'prf') {
    if (!file.prfSalt || !file.credential?.id || !file.credential.publicKey) {
      invalid('PRF backup without its salt or passkey');
    }
    if (file.passwordEncryption !== undefined) invalid('PRF backup with Argon2id parameters');
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
   * Create a BackupFile v4 encrypted with a password through Argon2id
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

    return toJson(
      await sealBackup(mnemonic, key, {
        version: BACKUP_FILE_VERSION,
        createdAt: new Date().toISOString(),
        encryptionMethod: 'password',
        passwordEncryption: {
          kdf: 'argon2id',
          salt: btoa(String.fromCharCode(...salt)),
          ...ARGON2ID_PARAMS,
        },
        ...(credential && { credential: { id: credential.id, publicKey: credential.publicKey } }),
        ...(username && { username }),
      })
    );
  }

  /**
   * Create a BackupFile v4 encrypted with a key derived from the passkey's
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

    return toJson(
      await sealBackup(mnemonic, encryptionKey, {
        version: BACKUP_FILE_VERSION,
        createdAt: new Date().toISOString(),
        encryptionMethod: 'prf',
        credential: { id: credential.id, publicKey: credential.publicKey },
        prfSalt,
        username,
      })
    );
  }

  /**
   * Restore from a PRF backup
   *
   * @param prfOutput - PRF output of the backup's passkey at prfSyncInput(backupFile.prfSalt)
   * @throws CryptoError on another passkey or a modified or corrupted file
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
    let mnemonic: string;
    try {
      mnemonic = await decryptData(
        backupFile.encryptedMnemonic,
        encryptionKey,
        backupAdditionalData(backupFile)
      );
    } catch (error) {
      throw new CryptoError('Wrong passkey, or the backup file was modified or corrupted', error);
    }

    return { mnemonic, ethereumAddress: await addressOf(mnemonic) };
  }

  /**
   * Restore from a password backup
   * Use case: User doesn't have passkey on this device yet
   *
   * @throws CryptoError on a wrong password or a modified or corrupted file
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
      mnemonic = await decryptData(backupFile.encryptedMnemonic, key, backupAdditionalData(backupFile));
    } catch (error) {
      throw new CryptoError('Wrong password, or the backup file was modified or corrupted', error);
    }

    return { mnemonic, ethereumAddress: await addressOf(mnemonic) };
  }

  /**
   * Parse a BackupFile v4 from JSON string or Blob
   *
   * @throws UnsupportedBackupVersionError for a file that isn't v4
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
