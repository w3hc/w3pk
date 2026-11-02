/**
 * Cross-Device Sync Type Definitions
 */

export interface DeviceInfo {
  id: string;
  name: string;
  platform: 'ios' | 'android' | 'macos' | 'windows' | 'linux' | 'unknown';
  lastActive: string;
  trusted: boolean;
  canRevoke: boolean; // False for current device
}

export interface SyncCapabilities {
  passkeysSync: boolean;
  platform: 'apple' | 'google' | 'microsoft' | 'none';
  estimatedDevices: number;
  syncEnabled: boolean;
}

export interface SyncStatus {
  enabled: boolean;
  devices: DeviceInfo[];
  lastSyncTime?: string;
  platform: string;
}
