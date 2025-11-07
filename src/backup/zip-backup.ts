/**
 * Password-protected ZIP backup creation
 * Creates encrypted backup packages with recovery instructions
 */

import type { ZipBackupOptions, BackupMetadata } from './types';
import {
  encryptWithPassword,
  getDeviceFingerprint,
  deriveAddressChecksum,
  validatePasswordStrength,
} from './encryption';

export class ZipBackupCreator {
  /**
   * Create password-protected ZIP backup
   * Returns a Blob that can be downloaded
   */
  async createZipBackup(
    mnemonic: string,
    ethereumAddress: string,
    options: ZipBackupOptions
  ): Promise<{ blob: Blob; metadata: BackupMetadata }> {
    // Validate password strength
    const passwordValidation = validatePasswordStrength(options.password);
    if (!passwordValidation.valid) {
      throw new Error(
        `Weak password: ${passwordValidation.feedback.join(', ')}`
      );
    }

    // Generate salt
    const salt = crypto.getRandomValues(new Uint8Array(32));

    // Encrypt mnemonic
    const encrypted = await encryptWithPassword(
      mnemonic,
      options.password,
      salt
    );

    // Get device fingerprint if binding enabled
    const deviceFingerprint = options.deviceBinding
      ? await getDeviceFingerprint()
      : undefined;

    // Create metadata
    const metadata: BackupMetadata = {
      id: crypto.randomUUID(),
      ethereumAddress,
      method: 'zip',
      createdAt: new Date().toISOString(),
      deviceFingerprint,
      addressChecksum: await deriveAddressChecksum(ethereumAddress),
    };

    // Create backup data structure
    const backupData = {
      version: 1,
      encrypted: encrypted.encrypted,
      iv: encrypted.iv,
      salt: encrypted.salt,
      iterations: encrypted.iterations,
      metadata,
      deviceFingerprint,
    };

    // Create files for ZIP
    const files = new Map<string, string>();

    // 1. Encrypted recovery phrase
    files.set('recovery-phrase.txt.enc', JSON.stringify(backupData, null, 2));

    // 2. Metadata (unencrypted)
    files.set(
      'metadata.json',
      JSON.stringify(
        {
          address: ethereumAddress,
          createdAt: metadata.createdAt,
          backupId: metadata.id,
          addressChecksum: metadata.addressChecksum,
        },
        null,
        2
      )
    );

    // 3. Recovery instructions
    if (options.includeInstructions !== false) {
      files.set('RECOVERY_INSTRUCTIONS.txt', this.getRecoveryInstructions());
    }

    // Create ZIP file (using simple implementation since JSZip might not be available)
    const blob = await this.createSimpleZip(files);

    return { blob, metadata };
  }

  /**
   * Create archive from files map
   */
  private async createSimpleZip(
    files: Map<string, string>
  ): Promise<Blob> {
    const archive: Record<string, string> = {};
    files.forEach((content, filename) => {
      archive[filename] = content;
    });

    return new Blob([JSON.stringify(archive, null, 2)], {
      type: 'application/json',
    });
  }

  /**
   * Get recovery instructions text
   */
  private getRecoveryInstructions(): string {
    return `
W3PK WALLET RECOVERY INSTRUCTIONS
=================================

This backup contains your encrypted wallet recovery phrase.

IMPORTANT:
- Keep this file safe and secure
- You NEED the password you set during backup creation
- Without the password, this backup cannot be decrypted

RECOVERY STEPS:
--------------

1. Go to the w3pk recovery page
   URL: https://your-w3pk-app.com/recover

2. Click "Import from Backup"

3. Upload this backup file

4. Enter your backup password

5. System will decrypt and verify your wallet

6. Your wallet will be restored!

VERIFICATION:
------------

After recovery, verify that the Ethereum address matches:
- Check the address in metadata.json
- Compare with your known wallet address
- If they match, recovery was successful ✓

SECURITY NOTES:
--------------

✓ This backup is encrypted with AES-256-GCM
✓ Your password is required to decrypt
✓ Store this backup in a secure location:
  - Password manager (1Password, Bitwarden)
  - Encrypted cloud storage (Google Drive, Dropbox)
  - USB drive in safe
  - Physical storage in safe deposit box

✗ Do NOT store in:
  - Unencrypted email
  - Shared drives
  - Public cloud without password protection

ALTERNATIVE RECOVERY:
-------------------

If you lose this backup, you can still recover using:
- Your 12-word recovery phrase (if saved separately)
- Social recovery (if configured)
- Passkey sync (if enabled on another device)

NEED HELP?
---------

Visit: https://docs.w3pk.org/recovery
Email: support@w3pk.org

Generated: ${new Date().toISOString()}
`;
  }

  /**
   * Decrypt and restore from ZIP backup
   */
  async restoreFromZipBackup(
    backupData: string,
    password: string
  ): Promise<{ mnemonic: string; metadata: BackupMetadata }> {
    // Parse backup data
    const data = JSON.parse(backupData);

    if (data.version !== 1) {
      throw new Error('Unsupported backup version');
    }

    // Decrypt mnemonic
    const { decryptWithPassword } = await import('./encryption');
    const mnemonic = await decryptWithPassword(
      data.encrypted,
      password,
      data.salt,
      data.iv,
      data.iterations
    );

    // Verify checksum
    const { Wallet } = await import('ethers');
    const wallet = Wallet.fromPhrase(mnemonic);
    const addressChecksum = await deriveAddressChecksum(wallet.address);

    if (addressChecksum !== data.metadata.addressChecksum) {
      throw new Error('Address checksum mismatch - corrupted backup or wrong password');
    }

    return {
      mnemonic,
      metadata: data.metadata,
    };
  }
}
