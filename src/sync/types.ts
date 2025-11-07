/**
 * Cross-Device Sync Type Definitions
 */

export interface SyncVault {
  id: string;
  encryptedData: string; // Encrypted mnemonic
  deviceFingerprints: string[]; // Devices that can decrypt
  syncMethod: 'icloud' | 'google' | 'microsoft' | 'custom';
  version: number;
  updatedAt: string;
}

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

export interface SyncResult {
  success: boolean;
  steps: SyncStep[];
}

export interface SyncStep {
  title: string;
  action: string;
  educational: string;
  status: 'waiting' | 'in-progress' | 'completed' | 'failed';
}
