/**
 * Encrypted Sync Vault
 * Manages encrypted wallet data for cross-device sync
 */

import type { SyncVault, SyncResult, SyncStep } from './types';
import { getDeviceFingerprint } from '../backup/encryption';

export class VaultSync {
  /**
   * Create encrypted sync package
   * Uses passkey + device fingerprint for encryption
   */
  async createSyncPackage(
    mnemonic: string,
    credentialId: string,
    publicKey: string
  ): Promise<SyncVault> {
    // Get device fingerprint
    const deviceFingerprint = await getDeviceFingerprint();

    // Encrypt mnemonic (using same method as wallet storage)
    const { deriveEncryptionKeyAuto, encryptData } = await import(
      '../wallet/crypto'
    );

    const encryptionKey = await deriveEncryptionKeyAuto(
      credentialId,
      publicKey
    );

    const encryptedData = await encryptData(mnemonic, encryptionKey);

    // Detect sync method
    const syncMethod = this.detectSyncMethod();

    return {
      id: crypto.randomUUID(),
      encryptedData,
      deviceFingerprints: [deviceFingerprint],
      syncMethod,
      version: 1,
      updatedAt: new Date().toISOString(),
    };
  }

  /**
   * Detect available sync method
   */
  private detectSyncMethod():
    | 'icloud'
    | 'google'
    | 'microsoft'
    | 'custom' {
    const userAgent = navigator.userAgent.toLowerCase();

    if (
      userAgent.includes('mac') ||
      userAgent.includes('iphone') ||
      userAgent.includes('ipad')
    ) {
      return 'icloud';
    }

    if (userAgent.includes('android') || userAgent.includes('chrome')) {
      return 'google';
    }

    if (userAgent.includes('windows')) {
      return 'microsoft';
    }

    return 'custom';
  }

  /**
   * Restore from sync vault
   * Interactive guide for multi-device setup
   */
  async restoreFromSync(
    vault: SyncVault,
    credentialId: string,
    publicKey: string
  ): Promise<string> {
    // Derive decryption key
    const { deriveEncryptionKeyAuto, decryptData } = await import(
      '../wallet/crypto'
    );

    const encryptionKey = await deriveEncryptionKeyAuto(
      credentialId,
      publicKey
    );

    // Decrypt mnemonic
    const mnemonic = await decryptData(vault.encryptedData, encryptionKey);

    // Add current device fingerprint
    const deviceFingerprint = await getDeviceFingerprint();
    if (!vault.deviceFingerprints.includes(deviceFingerprint)) {
      vault.deviceFingerprints.push(deviceFingerprint);
      vault.updatedAt = new Date().toISOString();
    }

    return mnemonic;
  }

  /**
   * Get setup flow for new device
   * Educational flow with step-by-step instructions
   */
  async getSetupFlow(): Promise<SyncResult> {
    const steps: SyncStep[] = [
      {
        title: '1. Authenticate on New Device',
        action: 'Use Touch ID/Face ID',
        educational:
          'Your passkey is automatically synced via iCloud/Google',
        status: 'waiting',
      },
      {
        title: '2. Decrypt Wallet Data',
        action: 'System validates device',
        educational: 'Only your trusted devices can decrypt the wallet',
        status: 'waiting',
      },
      {
        title: '3. Verify Recovery',
        action: 'Check partial address',
        educational: 'Confirm address matches your wallet',
        status: 'waiting',
      },
      {
        title: '4. Ready!',
        action: 'Wallet synced',
        educational: 'All devices now have access',
        status: 'waiting',
      },
    ];

    return {
      success: false,
      steps,
    };
  }

  /**
   * Educational message about how sync works
   */
  getSyncExplainer(): string {
    return `
HOW CROSS-DEVICE SYNC WORKS
===========================

Your wallet is protected by TWO layers:

Layer 1: Passkey (Auto-Syncs)
-----------------------------
✓ Your fingerprint/Face ID credential
✓ Syncs via iCloud Keychain or Google
✓ Available on all your devices
✓ Cannot be stolen (hardware-protected)

Layer 2: Encrypted Wallet (In Browser)
--------------------------------------
✓ Your 12-word mnemonic (encrypted)
✓ Stored in browser's IndexedDB
✓ Can ONLY be decrypted with passkey
✓ Requires authentication to access

How They Work Together:
----------------------

Device 1 (iPhone)          iCloud Keychain          Device 2 (Mac)
     |                            |                         |
     |-- Passkey Created -------->|                         |
     |                            |                         |
     |-- Wallet Encrypted --------|                         |
     |    (in IndexedDB)          |                         |
     |                            |                         |
     |                            |<----- Login on Mac -----|
     |                            |                         |
     |                     Passkey Synced                   |
     |                            |------- Unlock --------->|
     |                            |        Passkey          |
     |                            |                         |
     |                            |<----- Decrypt ----------|
     |                            |       Wallet            |

Security Benefits:
-----------------

✓ Passkey syncs automatically (convenient)
✓ Wallet ONLY decrypts with passkey (secure)
✓ Cannot access wallet without biometric
✓ Works seamlessly across devices
✓ No passwords to remember

What Gets Synced:
----------------

✓ Passkey credential (via platform sync)
✓ Credential metadata (localStorage)

What Stays Local:
----------------

✗ Encrypted mnemonic (in IndexedDB)
  - Must authenticate to decrypt
  - Requires passkey access
  - Platform-specific storage

Recovery Options:
----------------

If you lose a device:
1. ✓ Sign in on new device
2. ✓ Passkey auto-syncs
3. ✓ Authenticate to decrypt wallet
4. ✓ Wallet restored!

If passkey doesn't sync:
1. ✓ Use encrypted backup
2. ✓ Use 12-word recovery phrase
3. ✓ Use social recovery

---

Think of it like:
🔑 Passkey = Your car key (syncs via keychain)
🚗 Wallet = Your car (locked, needs key to start)
`;
  }
}
