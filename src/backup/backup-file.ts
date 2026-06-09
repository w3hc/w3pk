/**
 * Simplified Backup File Manager
 *
 * Creates a universal "floppy disk" backup file that can be used to:
 * 1. Restore wallet with existing passkey (same or synced device)
 * 2. Register new passkey with this wallet (fresh device)
 * 3. Sync wallet across devices
 * 4. Split among guardians for social recovery (via Shamir)
 */

import type { BackupFile } from './types';
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

export class BackupFileManager {
  /**
   * Create backup file encrypted with password
   * This is the primary method for creating portable backups
   *
   * @param mnemonic - The BIP39 mnemonic to encrypt
   * @param ethereumAddress - The Ethereum address for verification
   * @param password - User's password for encryption (required for security)
   */
  async createPasswordBackup(
    mnemonic: string,
    ethereumAddress: string,
    password: string
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
