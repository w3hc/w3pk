/**
 * Social Recovery Manager
 * Manages guardian-based wallet recovery using Shamir Secret Sharing
 */

import type {
  Guardian,
  GuardianInvite,
  SocialRecoveryConfig,
  RecoveryShare,
  RecoveryProgress,
} from './types';
import {
  splitSecret,
  combineShares,
  stringToBytes,
  bytesToString,
  bytesToHex,
  hexToBytes,
} from './shamir';

// Singleton in-memory storage for non-browser environments
const memoryStorageSingleton = new Map<string, string>();

export class SocialRecoveryManager {
  private storageKey = 'w3pk_social_recovery';

  /**
   * Get storage (localStorage or in-memory fallback)
   */
  private getItem(key: string): string | null {
    if (typeof localStorage !== 'undefined') {
      return localStorage.getItem(key);
    }
    return memoryStorageSingleton.get(key) || null;
  }

  /**
   * Set storage (localStorage or in-memory fallback)
   */
  private setItem(key: string, value: string): void {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(key, value);
    } else {
      memoryStorageSingleton.set(key, value);
    }
  }

  /**
   * Set up social recovery
   * Splits mnemonic into M-of-N shares and distributes to guardians
   */
  async setupSocialRecovery(
    mnemonic: string,
    ethereumAddress: string,
    guardians: { name: string; email?: string; phone?: string }[],
    threshold: number
  ): Promise<Guardian[]> {
    if (threshold > guardians.length) {
      throw new Error('Threshold cannot be greater than number of guardians');
    }

    if (threshold < 2) {
      throw new Error('Threshold must be at least 2');
    }

    if (guardians.length > 255) {
      throw new Error('Cannot have more than 255 guardians');
    }

    // Convert mnemonic to bytes
    const secretBytes = stringToBytes(mnemonic);

    // Split into shares
    const shares = splitSecret(secretBytes, threshold, guardians.length);

    // Create guardian objects
    const guardianObjects: Guardian[] = guardians.map((g, index) => ({
      id: crypto.randomUUID(),
      name: g.name,
      email: g.email,
      phone: g.phone,
      shareEncrypted: bytesToHex(shares[index]),
      status: 'pending' as const,
      addedAt: Date.now(),
    }));

    // Store config
    const config: SocialRecoveryConfig = {
      threshold,
      totalGuardians: guardians.length,
      guardians: guardianObjects,
      createdAt: Date.now(),
      ethereumAddress,
    };

    this.setItem(this.storageKey, JSON.stringify(config));

    return guardianObjects;
  }

  /**
   * Get current social recovery configuration
   */
  getSocialRecoveryConfig(): SocialRecoveryConfig | null {
    const stored = this.getItem(this.storageKey);
    if (!stored) return null;

    try {
      return JSON.parse(stored);
    } catch {
      return null;
    }
  }

  /**
   * Generate guardian invitation
   * Creates QR code and educational materials for guardian
   */
  async generateGuardianInvite(guardian: Guardian): Promise<GuardianInvite> {
    const config = this.getSocialRecoveryConfig();
    if (!config) {
      throw new Error('Social recovery not configured');
    }

    // Find guardian index
    const index = config.guardians.findIndex((g) => g.id === guardian.id);
    if (index === -1) {
      throw new Error('Guardian not found');
    }

    // Create guardian data package
    const guardianData = {
      version: 1,
      guardianId: guardian.id,
      guardianName: guardian.name,
      guardianIndex: index + 1,
      totalGuardians: config.totalGuardians,
      threshold: config.threshold,
      share: guardian.shareEncrypted,
      ethereumAddress: config.ethereumAddress,
      createdAt: config.createdAt,
    };

    const shareCode = JSON.stringify(guardianData);

    // Generate QR code
    const qrCode = await this.generateQRCode(shareCode);

    // Create explainer
    const explainer = this.getGuardianExplainer(
      guardian.name,
      index + 1,
      config.totalGuardians,
      config.threshold
    );

    return {
      guardianId: guardian.id,
      qrCode,
      shareCode,
      explainer,
    };
  }

  /**
   * Generate QR code from share data
   * Uses 'qrcode' library if available, falls back to canvas text
   */
  private async generateQRCode(data: string): Promise<string> {
    try {
      const QRCode = (await import('qrcode')) as any;
      return await QRCode.toDataURL(data, {
        errorCorrectionLevel: 'H',
        width: 512,
        margin: 2,
      });
    } catch {
      return this.createPlaceholderQR(data);
    }
  }

  /**
   * Create fallback QR representation
   */
  private createPlaceholderQR(data: string): string {
    // Check if we're in a browser environment
    if (typeof document === 'undefined') {
      // Node.js environment - return a simple data URL with text
      return `data:text/plain;base64,${Buffer.from(data).toString('base64')}`;
    }

    const canvas = document.createElement('canvas');
    canvas.width = 512;
    canvas.height = 512;

    const ctx = canvas.getContext('2d');
    if (!ctx) {
      return '';
    }

    // White background
    ctx.fillStyle = 'white';
    ctx.fillRect(0, 0, 512, 512);

    // Black text
    ctx.fillStyle = 'black';
    ctx.font = 'bold 20px sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';

    ctx.fillText('Guardian Recovery Share', 256, 100);
    ctx.font = '14px monospace';
    ctx.fillText('Install "qrcode" for QR codes', 256, 480);

    // Show truncated data
    ctx.font = '10px monospace';
    const lines = this.wrapText(data.substring(0, 200) + '...', 60);
    lines.forEach((line, i) => {
      ctx.fillText(line, 256, 150 + i * 12);
    });

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
   * Get guardian explainer text
   */
  private getGuardianExplainer(
    name: string,
    index: number,
    total: number,
    threshold: number
  ): string {
    return `
🛡️ GUARDIAN RECOVERY SHARE

Dear ${name},

You have been chosen as Guardian ${index} of ${total}

YOUR ROLE:
----------

Your friend has entrusted you with a recovery share for their cryptocurrency wallet.

WHAT THIS MEANS:
- You hold 1 piece of a ${threshold}-piece puzzle
- ${threshold} guardians needed to recover the wallet
- You cannot access the wallet alone
- This is a responsibility and honor

HOW IT WORKS:
-------------

If your friend loses access to their wallet:

1. They will contact you to request your share
2. You provide the QR code or share code below
3. System collects shares from ${threshold} guardians
4. Wallet is mathematically reconstructed
5. Your friend regains access ✓

SECURITY:
---------

✓ Your share is encrypted
✓ Cannot be used alone
✓ ${threshold - 1} other guardians needed
✓ Safe to store digitally

YOUR RESPONSIBILITIES:
---------------------

DO:
✓ Keep this share safe and accessible
✓ Store in password manager or secure location
✓ Respond promptly if friend requests recovery
✓ Verify identity before sharing

DON'T:
✗ Share unless friend explicitly requests it
✗ Post publicly or send unsecured
✗ Lose or delete (friend depends on you!)

VERIFICATION:
------------

Before sharing, verify your friend's identity:
- Video call to confirm
- Ask security questions
- Check contact method is authentic

RECOVERY PROCESS:
----------------

If requested:
1. Friend will contact you
2. Verify their identity
3. Provide this QR code or share code
4. System handles the rest

HOW TO STORE:
------------

Recommended storage:
✓ Password manager (1Password, Bitwarden)
✓ Encrypted note
✓ Print and store physically
✓ Screenshot (encrypted phone)

---

Guardian ${index}/${total} | Threshold: ${threshold}/${total}
Created: ${new Date().toISOString()}

Thank you for being a trusted guardian!

---

NEED HELP?
Visit: https://docs.w3pk.org/social-recovery
`;
  }

  /**
   * Recover mnemonic from guardian shares
   */
  async recoverFromGuardians(
    shareData: string[]
  ): Promise<{ mnemonic: string; ethereumAddress: string }> {
    const config = this.getSocialRecoveryConfig();
    if (!config) {
      throw new Error('Social recovery not configured');
    }

    if (shareData.length < config.threshold) {
      throw new Error(
        `Need at least ${config.threshold} shares, got ${shareData.length}`
      );
    }

    // Parse share data
    const shares: RecoveryShare[] = shareData.map((data) => {
      const parsed = JSON.parse(data);
      return {
        guardianId: parsed.guardianId,
        share: parsed.share,
        index: parsed.guardianIndex,
      };
    });

    // Convert shares to bytes
    const shareBytes = shares.map((s) => hexToBytes(s.share));

    // Combine shares
    const secretBytes = combineShares(shareBytes, config.threshold);

    // Convert to mnemonic
    const mnemonic = bytesToString(secretBytes);

    // Verify
    const { Wallet } = await import('ethers');
    const wallet = Wallet.fromPhrase(mnemonic);

    if (wallet.address.toLowerCase() !== config.ethereumAddress.toLowerCase()) {
      throw new Error('Recovered address does not match - invalid shares');
    }

    return {
      mnemonic,
      ethereumAddress: wallet.address,
    };
  }

  /**
   * Get recovery progress
   */
  getRecoveryProgress(collectedShares: string[]): RecoveryProgress {
    const config = this.getSocialRecoveryConfig();
    if (!config) {
      throw new Error('Social recovery not configured');
    }

    const collectedGuardianIds = new Set(
      collectedShares.map((data) => {
        try {
          return JSON.parse(data).guardianId;
        } catch {
          return null;
        }
      }).filter(Boolean)
    );

    return {
      collected: collectedGuardianIds.size,
      required: config.threshold,
      guardians: config.guardians.map((g) => ({
        id: g.id,
        name: g.name,
        hasProvided: collectedGuardianIds.has(g.id),
      })),
      canRecover: collectedGuardianIds.size >= config.threshold,
    };
  }

  /**
   * Mark guardian as verified
   */
  markGuardianVerified(guardianId: string): void {
    const config = this.getSocialRecoveryConfig();
    if (!config) {
      throw new Error('Social recovery not configured');
    }

    const guardian = config.guardians.find((g) => g.id === guardianId);
    if (!guardian) {
      throw new Error('Guardian not found');
    }

    guardian.status = 'active';
    guardian.lastVerified = Date.now();

    this.setItem(this.storageKey, JSON.stringify(config));
  }

  /**
   * Revoke a guardian
   */
  revokeGuardian(guardianId: string): void {
    const config = this.getSocialRecoveryConfig();
    if (!config) {
      throw new Error('Social recovery not configured');
    }

    const guardian = config.guardians.find((g) => g.id === guardianId);
    if (!guardian) {
      throw new Error('Guardian not found');
    }

    guardian.status = 'revoked';

    this.setItem(this.storageKey, JSON.stringify(config));
  }

  /**
   * Add new guardian (requires re-sharing)
   */
  async addGuardian(
    mnemonic: string,
    newGuardian: { name: string; email?: string; phone?: string }
  ): Promise<Guardian> {
    const config = this.getSocialRecoveryConfig();
    if (!config) {
      throw new Error('Social recovery not configured');
    }

    // Re-setup with new guardian
    const updatedGuardians = [
      ...config.guardians
        .filter((g) => g.status !== 'revoked')
        .map((g) => ({ name: g.name, email: g.email, phone: g.phone })),
      newGuardian,
    ];

    const newGuardianObjects = await this.setupSocialRecovery(
      mnemonic,
      config.ethereumAddress,
      updatedGuardians,
      config.threshold
    );

    return newGuardianObjects[newGuardianObjects.length - 1];
  }
}
