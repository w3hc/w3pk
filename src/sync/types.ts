/**
 * Cross-Device Sync Type Definitions
 */

export interface SyncCapabilities {
  passkeysSync: boolean;
  platform: 'apple' | 'google' | 'microsoft' | 'none';
  estimatedDevices: number;
  syncEnabled: boolean;
}
