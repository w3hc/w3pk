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
import {
  deriveEncryptionKeyFromWebAuthn,
  encryptData,
  decryptData,
} from '../wallet/crypto';
import { CryptoError } from '../core/errors';
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
   * Create backup file encrypted with existing passkey
   * Useful for syncing to devices where the passkey is already synced
   */
  async createPasskeyBackup(
    mnemonic: string,
    ethereumAddress: string,
    credentialId: string,
    publicKey: string
  ): Promise<{ backupFile: BackupFile; json: string; blob: Blob }> {
    const encryptionKey = await deriveEncryptionKeyFromWebAuthn(
      credentialId,
      publicKey
    );

    const encryptedMnemonic = await encryptData(mnemonic, encryptionKey);
    const addressChecksum = await deriveAddressChecksum(ethereumAddress);

    // Generate public key fingerprint
    const encoder = new TextEncoder();
    const pkBuffer = encoder.encode(publicKey);
    const hashBuffer = await crypto.subtle.digest('SHA-256', pkBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const publicKeyFingerprint = hashArray
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
      .substring(0, 16);

    const backupFile: BackupFile = {
      createdAt: new Date().toISOString(),
      ethereumAddress,
      encryptedMnemonic,
      encryptionMethod: 'passkey',
      credentialId,
      publicKeyFingerprint,
      addressChecksum,
    };

    const json = JSON.stringify(backupFile, null, 2);
    const blob = new Blob([json], { type: 'application/json' });

    return { backupFile, json, blob };
  }

  /**
   * Create hybrid backup encrypted with both password AND passkey
   * Most secure option - requires both factors to decrypt
   */
  async createHybridBackup(
    mnemonic: string,
    ethereumAddress: string,
    password: string,
    credentialId: string,
    publicKey: string
  ): Promise<{ backupFile: BackupFile; json: string; blob: Blob }> {
    // First encrypt with passkey
    const passkeyKey = await deriveEncryptionKeyFromWebAuthn(
      credentialId,
      publicKey
    );
    const passkeyEncrypted = await encryptData(mnemonic, passkeyKey);

    // Then encrypt the result with password
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const passwordEncrypted = await encryptWithPassword(
      passkeyEncrypted,
      password,
      salt
    );

    const addressChecksum = await deriveAddressChecksum(ethereumAddress);

    // Generate public key fingerprint
    const encoder = new TextEncoder();
    const pkBuffer = encoder.encode(publicKey);
    const hashBuffer = await crypto.subtle.digest('SHA-256', pkBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const publicKeyFingerprint = hashArray
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
      .substring(0, 16);

    const backupFile: BackupFile = {
      createdAt: new Date().toISOString(),
      ethereumAddress,
      encryptedMnemonic: passwordEncrypted.encrypted,
      encryptionMethod: 'hybrid',
      credentialId,
      publicKeyFingerprint,
      passwordEncryption: {
        salt: passwordEncrypted.salt,
        iv: passwordEncrypted.iv,
        iterations: passwordEncrypted.iterations,
      },
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
   * Restore from backup file using existing passkey
   * Use case: User has passkey synced to this device and wants to restore wallet
   */
  async restoreWithExistingPasskey(
    backupFile: BackupFile,
    credentialId: string,
    publicKey: string
  ): Promise<{ mnemonic: string; ethereumAddress: string }> {
    if (backupFile.encryptionMethod === 'password') {
      throw new Error(
        'This backup is password-protected. Use restoreWithPassword() instead.'
      );
    }
    if (backupFile.encryptionMethod === 'prf') {
      throw new Error('This backup is PRF-encrypted. Use restoreWithPrf() instead.');
    }

    // Verify credential matches
    if (backupFile.credentialId && backupFile.credentialId !== credentialId) {
      throw new Error(
        'Credential ID mismatch. This backup was created with a different passkey.'
      );
    }

    let mnemonic: string;

    if (backupFile.encryptionMethod === 'passkey') {
      // Decrypt with passkey only
      const encryptionKey = await deriveEncryptionKeyFromWebAuthn(
        credentialId,
        publicKey
      );
      mnemonic = await decryptData(backupFile.encryptedMnemonic, encryptionKey);
    } else {
      // hybrid mode requires password too
      throw new Error(
        'This backup requires both passkey and password. Use restoreWithHybrid() instead.'
      );
    }

    // Verify address checksum
    const { Wallet } = await import('ethers');
    const wallet = Wallet.fromPhrase(mnemonic);
    const addressChecksum = await deriveAddressChecksum(wallet.address);

    if (addressChecksum !== backupFile.addressChecksum) {
      throw new Error(
        'Address checksum mismatch - corrupted backup or decryption failure'
      );
    }

    return {
      mnemonic,
      ethereumAddress: backupFile.ethereumAddress,
    };
  }

  /**
   * Restore from backup file using password
   * Use case: User doesn't have passkey on this device yet
   */
  async restoreWithPassword(
    backupFile: BackupFile,
    password: string
  ): Promise<{ mnemonic: string; ethereumAddress: string }> {
    if (!backupFile.passwordEncryption) {
      throw new Error('This backup is not password-protected.');
    }

    let mnemonic: string;

    if (backupFile.encryptionMethod === 'password') {
      // Decrypt with password only
      mnemonic = await decryptWithPassword(
        backupFile.encryptedMnemonic,
        password,
        backupFile.passwordEncryption.salt,
        backupFile.passwordEncryption.iv,
        backupFile.passwordEncryption.iterations
      );
    } else if (backupFile.encryptionMethod === 'hybrid') {
      throw new Error(
        'This backup requires both passkey and password. Use restoreWithHybrid() instead.'
      );
    } else {
      throw new Error(
        'This backup is passkey-only. Use restoreWithExistingPasskey() instead.'
      );
    }

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
   * Restore from hybrid backup (requires both passkey and password)
   */
  async restoreWithHybrid(
    backupFile: BackupFile,
    password: string,
    credentialId: string,
    publicKey: string
  ): Promise<{ mnemonic: string; ethereumAddress: string }> {
    if (backupFile.encryptionMethod !== 'hybrid') {
      throw new Error('This backup is not a hybrid backup.');
    }

    if (!backupFile.passwordEncryption) {
      throw new Error('Missing password encryption data in hybrid backup.');
    }

    // First decrypt with password
    const passwordDecrypted = await decryptWithPassword(
      backupFile.encryptedMnemonic,
      password,
      backupFile.passwordEncryption.salt,
      backupFile.passwordEncryption.iv,
      backupFile.passwordEncryption.iterations
    );

    // Then decrypt with passkey
    const passkeyKey = await deriveEncryptionKeyFromWebAuthn(
      credentialId,
      publicKey
    );
    const mnemonic = await decryptData(passwordDecrypted, passkeyKey);

    // Verify address checksum
    const { Wallet } = await import('ethers');
    const wallet = Wallet.fromPhrase(mnemonic);
    const addressChecksum = await deriveAddressChecksum(wallet.address);

    if (addressChecksum !== backupFile.addressChecksum) {
      throw new Error(
        'Address checksum mismatch - corrupted backup or decryption failure'
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
