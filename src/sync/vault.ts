/**
 * Sync Vault
 * Educational guide to cross-device sync
 */

import type { SyncResult, SyncStep } from './types';

export class VaultSync {
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
✓ Stored in browser's localStorage
✓ Can ONLY be decrypted with passkey
✓ Requires authentication to access

How They Work Together:
----------------------

Device 1 (iPhone)          iCloud Keychain          Device 2 (Mac)
     |                            |                         |
     |-- Passkey Created -------->|                         |
     |                            |                         |
     |-- Wallet Encrypted --------|                         |
     |    (in localStorage)       |                         |
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

✗ Encrypted mnemonic (in localStorage)
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
