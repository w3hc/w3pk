/**
 * Platform Detection for Passkey Sync
 * Detects available sync platforms (iCloud, Google, Microsoft)
 */

import type { SyncCapabilities } from './types';

export class PlatformDetector {
  /**
   * Detect available sync capabilities
   * Shows what's automatically protecting the user
   */
  async detectSyncCapabilities(): Promise<SyncCapabilities> {
    const platform = this.detectPlatform();
    const passkeysSync = await this.checkPasskeySync();
    const estimatedDevices = this.estimateDeviceCount();

    return {
      passkeysSync,
      platform,
      estimatedDevices,
      syncEnabled: passkeysSync && platform !== 'none',
    };
  }

  /**
   * Detect user's platform
   */
  private detectPlatform(): 'apple' | 'google' | 'microsoft' | 'none' {
    const userAgent = navigator.userAgent.toLowerCase();

    // Check for Apple devices
    if (
      userAgent.includes('mac') ||
      userAgent.includes('iphone') ||
      userAgent.includes('ipad') ||
      userAgent.includes('ipod')
    ) {
      return 'apple';
    }

    // Check for Android
    if (userAgent.includes('android')) {
      return 'google';
    }

    // Check for Windows
    if (userAgent.includes('windows')) {
      return 'microsoft';
    }

    return 'none';
  }

  /**
   * Check if passkey sync is supported
   */
  private async checkPasskeySync(): Promise<boolean> {
    if (!window.PublicKeyCredential) {
      return false;
    }

    try {
      // Check if platform authenticator is available
      const available =
        await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      return available;
    } catch {
      return false;
    }
  }

  /**
   * Estimate number of synced devices
   * Note: This is a rough estimate, actual count requires server-side tracking
   */
  private estimateDeviceCount(): number {
    // In a real implementation, this would:
    // 1. Check server-side records of successful logins
    // 2. Query platform-specific APIs if available
    // 3. Use credential storage to count unique device fingerprints

    // For now, return minimum of 1 (current device)
    return 1;
  }

  /**
   * Get platform-specific educational message
   */
  getPlatformEducation(platform: 'apple' | 'google' | 'microsoft' | 'none'): string {
    switch (platform) {
      case 'apple':
        return `
🍎 Apple iCloud Keychain

Your passkey automatically syncs across:
- iPhone
- iPad
- Mac
- Apple Watch (for authentication)

Requirements:
✓ iCloud Keychain enabled in Settings
✓ Signed in to iCloud
✓ Two-factor authentication enabled

How it works:
1. Create passkey on this device
2. iCloud encrypts and syncs it
3. Available on all your Apple devices
4. End-to-end encrypted

Security:
- Apple cannot access your passkeys
- Synced with end-to-end encryption
- Requires device unlock to use
`;

      case 'google':
        return `
🤖 Google Password Manager

Your passkey automatically syncs across:
- Android phones/tablets
- Chrome browser (all platforms)
- ChromeOS devices

Requirements:
✓ Signed in to Google Account
✓ Sync enabled in Chrome
✓ Screen lock configured

How it works:
1. Create passkey on this device
2. Google encrypts and syncs it
3. Available on all signed-in devices
4. End-to-end encrypted

Security:
- Google cannot access your passkeys
- Synced with end-to-end encryption
- Requires screen unlock to use
`;

      case 'microsoft':
        return `
🪟 Windows Hello

Your passkey is tied to this Windows device.

Note: Limited cross-device sync
- Passkeys stored in Windows Credential Manager
- Tied to this PC's TPM chip
- Does NOT sync to other devices automatically

For cross-device access:
- Use encrypted backup instead
- Or set up social recovery

Security:
- Hardware-protected (TPM)
- Requires Windows Hello (PIN/biometric)
- Very secure but not portable
`;

      case 'none':
        return `
⚠️ Platform Sync Not Available

Your passkey will be stored on this device only.

Recommendation:
✓ Create encrypted backup (password-protected)
✓ Set up social recovery
✓ Save your 12-word recovery phrase

This ensures you can recover if:
- Device is lost/stolen
- Device is damaged
- You switch devices
`;
    }
  }

  /**
   * Get sync setup instructions
   */
  getSyncInstructions(platform: 'apple' | 'google' | 'microsoft' | 'none'): string[] {
    switch (platform) {
      case 'apple':
        return [
          'Open Settings on your iPhone/iPad/Mac',
          'Tap your name at the top',
          'Tap "iCloud"',
          'Enable "Keychain"',
          'Enable "iCloud Backup" (recommended)',
        ];

      case 'google':
        return [
          'Open Chrome Settings',
          'Click "You and Google"',
          'Enable "Sync"',
          'Ensure "Passwords" is checked',
          'Sign in on other devices with same Google account',
        ];

      case 'microsoft':
        return [
          'Windows Hello sync is limited',
          'Consider using:',
          '- Encrypted ZIP backup',
          '- Social recovery',
          '- Cloud backup (password-protected)',
        ];

      case 'none':
        return [
          'Platform sync not available',
          'Use alternative backup methods:',
          '- Create encrypted ZIP backup',
          '- Set up social recovery',
          '- Save recovery phrase securely',
        ];
    }
  }
}
