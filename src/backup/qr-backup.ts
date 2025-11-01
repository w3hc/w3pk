/**
 * QR Code backup creation
 * Generates scannable QR codes with encrypted mnemonic
 */

import type { QRBackupOptions } from './types';
import {
  encryptWithPassword,
  deriveAddressChecksum,
} from './encryption';

export class QRBackupCreator {
  /**
   * Create QR code backup
   * @param mnemonic - The mnemonic to backup
   * @param ethereumAddress - Associated Ethereum address
   * @param options - QR backup options
   * @returns Data URL for QR code image and instructions
   */
  async createQRBackup(
    mnemonic: string,
    ethereumAddress: string,
    options: QRBackupOptions = {}
  ): Promise<{
    qrCodeDataURL: string;
    rawData: string;
    instructions: string;
  }> {
    const errorCorrection = options.errorCorrection || 'H'; // 30% damage tolerance

    let qrData: any;

    if (options.password) {
      // Encrypted QR code
      const salt = crypto.getRandomValues(new Uint8Array(32));
      const encrypted = await encryptWithPassword(
        mnemonic,
        options.password,
        salt
      );

      qrData = {
        version: 1,
        type: 'encrypted',
        data: encrypted.encrypted,
        iv: encrypted.iv,
        salt: encrypted.salt,
        iterations: encrypted.iterations,
        checksum: await deriveAddressChecksum(ethereumAddress),
      };
    } else {
      // Plain QR code (not recommended for production wallets)
      qrData = {
        version: 1,
        type: 'plain',
        data: mnemonic,
        checksum: await deriveAddressChecksum(ethereumAddress),
      };
    }

    const rawData = JSON.stringify(qrData);

    // Generate QR code
    const qrCodeDataURL = await this.generateQRCode(rawData, errorCorrection);

    // Generate instructions
    const instructions = this.getInstructions(
      ethereumAddress,
      !!options.password
    );

    return {
      qrCodeDataURL,
      rawData,
      instructions,
    };
  }

  /**
   * Generate QR code from data
   * Uses 'qrcode' library if available, falls back to text representation
   */
  private async generateQRCode(
    data: string,
    errorCorrection: string
  ): Promise<string> {
    try {
      const QRCode = (await import('qrcode')).default;
      return await QRCode.toDataURL(data, {
        errorCorrectionLevel: errorCorrection as any,
        width: 512,
        margin: 2,
      });
    } catch {
      return this.createFallbackQRDataURL(data);
    }
  }

  /**
   * Create fallback QR representation
   */
  private createFallbackQRDataURL(data: string): string {
    // Check if we're in a browser environment
    if (typeof document === 'undefined') {
      // Node.js environment - return a simple data URL with text
      return `data:text/plain;base64,${Buffer.from(data).toString('base64')}`;
    }

    // Create a canvas with text (fallback)
    const canvas = document.createElement('canvas');
    canvas.width = 512;
    canvas.height = 512;

    const ctx = canvas.getContext('2d');
    if (!ctx) {
      throw new Error('Canvas not supported');
    }

    // White background
    ctx.fillStyle = 'white';
    ctx.fillRect(0, 0, 512, 512);

    // Black text
    ctx.fillStyle = 'black';
    ctx.font = '12px monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';

    // Wrap text
    const lines = this.wrapText(data, 50);
    const lineHeight = 14;
    const startY = 256 - (lines.length * lineHeight) / 2;

    lines.forEach((line, i) => {
      ctx.fillText(line, 256, startY + i * lineHeight);
    });

    // Add note
    ctx.font = 'bold 16px sans-serif';
    ctx.fillText('Install "qrcode" package for QR codes', 256, 480);

    return canvas.toDataURL('image/png');
  }

  /**
   * Wrap text for display
   */
  private wrapText(text: string, maxLength: number): string[] {
    const lines: string[] = [];
    for (let i = 0; i < text.length; i += maxLength) {
      lines.push(text.substring(i, i + maxLength));
    }
    return lines;
  }

  /**
   * Get recovery instructions for QR backup
   */
  private getInstructions(
    ethereumAddress: string,
    encrypted: boolean
  ): string {
    return `
W3PK QR CODE BACKUP
==================

Ethereum Address: ${ethereumAddress}
Backup Date: ${new Date().toISOString()}
Type: ${encrypted ? 'Encrypted' : 'Plain'}

STORAGE INSTRUCTIONS:
--------------------

📸 Print this QR code and store securely:
  ✓ Safe deposit box
  ✓ Home safe
  ✓ Trusted family member
  ✓ Multiple physical locations

⚠️  DO NOT:
  ✗ Store digitally (screenshot/photo)
  ✗ Upload to cloud
  ✗ Email or message
  ✗ Share publicly

RECOVERY STEPS:
--------------

1. Scan QR code with your phone camera or QR scanner app

2. Import the scanned data to w3pk recovery page

3. ${encrypted ? 'Enter your backup password' : 'No password needed (plain backup)'}

4. Wallet will be restored

SECURITY NOTES:
--------------

${
  encrypted
    ? `
✓ This QR code is ENCRYPTED
✓ Password required to decrypt
✓ Safe to store in multiple locations
✓ Share with trusted family (they can't access without password)
`
    : `
⚠️  This QR code is NOT ENCRYPTED
⚠️  Anyone with access can recover your wallet
⚠️  Store with maximum security
⚠️  Do not photograph or copy
`
}

ERROR CORRECTION:
----------------

This QR code has HIGH error correction (30% damage tolerance)
- Can survive partial damage
- Can handle folding/creasing
- Ensure good print quality

VERIFICATION:
------------

Address checksum is embedded in QR code
After scanning, verify address matches: ${ethereumAddress}

ALTERNATIVE RECOVERY:
-------------------

If QR code is lost/damaged, you can still recover using:
- Encrypted ZIP backup
- Social recovery
- Passkey sync
- Manual mnemonic entry (if you wrote down the words)

---

Generated by w3pk Recovery System
https://docs.w3pk.org/recovery
`;
  }

  /**
   * Restore from scanned QR data
   */
  async restoreFromQR(
    qrData: string,
    password?: string
  ): Promise<{ mnemonic: string; ethereumAddress: string }> {
    const data = JSON.parse(qrData);

    if (data.version !== 1) {
      throw new Error('Unsupported QR backup version');
    }

    let mnemonic: string;

    if (data.type === 'encrypted') {
      if (!password) {
        throw new Error('Password required for encrypted QR backup');
      }

      const { decryptWithPassword } = await import('./encryption');
      mnemonic = await decryptWithPassword(
        data.data,
        password,
        data.salt,
        data.iv,
        data.iterations
      );
    } else if (data.type === 'plain') {
      mnemonic = data.data;
    } else {
      throw new Error('Unknown QR backup type');
    }

    // Verify checksum
    const { Wallet } = await import('ethers');
    const wallet = Wallet.fromPhrase(mnemonic);
    const addressChecksum = await deriveAddressChecksum(wallet.address);

    if (addressChecksum !== data.checksum) {
      throw new Error('Address checksum mismatch - corrupted QR or wrong password');
    }

    return {
      mnemonic,
      ethereumAddress: wallet.address,
    };
  }
}
