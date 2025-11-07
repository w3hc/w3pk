/**
 * Device Manager
 * Track and manage trusted devices with wallet access
 */

import type { DeviceInfo, SyncStatus } from './types';
import { getDeviceFingerprint } from '../backup/encryption';

export class DeviceManager {
  private storageKey = 'w3pk_devices';

  /**
   * Register current device
   */
  async registerDevice(): Promise<DeviceInfo> {
    const deviceInfo: DeviceInfo = {
      id: await getDeviceFingerprint(),
      name: this.getDeviceName(),
      platform: this.detectPlatform(),
      lastActive: new Date().toISOString(),
      trusted: true,
      canRevoke: false, // Current device cannot be revoked
    };

    // Store device info
    const devices = await this.getDevices();
    const existing = devices.find((d) => d.id === deviceInfo.id);

    if (!existing) {
      devices.push(deviceInfo);
      localStorage.setItem(this.storageKey, JSON.stringify(devices));
    } else {
      // Update last active
      existing.lastActive = new Date().toISOString();
      localStorage.setItem(this.storageKey, JSON.stringify(devices));
    }

    return deviceInfo;
  }

  /**
   * Get all registered devices
   */
  async getDevices(): Promise<DeviceInfo[]> {
    const stored = localStorage.getItem(this.storageKey);
    if (!stored) {
      return [];
    }

    try {
      return JSON.parse(stored);
    } catch {
      return [];
    }
  }

  /**
   * Get sync status with device list
   */
  async getSyncStatus(): Promise<SyncStatus> {
    const devices = await this.getDevices();
    const currentDeviceId = await getDeviceFingerprint();

    // Mark current device as not revokable
    devices.forEach((device) => {
      device.canRevoke = device.id !== currentDeviceId;
    });

    // Sort by last active (most recent first)
    devices.sort((a, b) => new Date(b.lastActive).getTime() - new Date(a.lastActive).getTime());

    const platform = this.detectPlatform();
    const lastSyncTime = devices.length > 1
      ? new Date(Math.max(...devices.map((d) => new Date(d.lastActive).getTime()))).toISOString()
      : undefined;

    return {
      enabled: devices.length > 1,
      devices,
      lastSyncTime,
      platform: this.getPlatformName(platform),
    };
  }

  /**
   * Revoke a device
   */
  async revokeDevice(deviceId: string): Promise<void> {
    const devices = await this.getDevices();
    const currentDeviceId = await getDeviceFingerprint();

    // Prevent revoking current device
    if (deviceId === currentDeviceId) {
      throw new Error('Cannot revoke current device');
    }

    // Remove device
    const filtered = devices.filter((d) => d.id !== deviceId);
    localStorage.setItem(this.storageKey, JSON.stringify(filtered));
  }

  /**
   * Update device last active timestamp
   */
  async updateLastActive(): Promise<void> {
    const devices = await this.getDevices();
    const currentDeviceId = await getDeviceFingerprint();

    const device = devices.find((d) => d.id === currentDeviceId);
    if (device) {
      device.lastActive = new Date().toISOString();
      localStorage.setItem(this.storageKey, JSON.stringify(devices));
    }
  }

  /**
   * Get device name
   */
  private getDeviceName(): string {
    const platform = this.detectPlatform();
    const ua = navigator.userAgent;

    if (platform === 'ios') {
      if (ua.includes('iPhone')) return 'iPhone';
      if (ua.includes('iPad')) return 'iPad';
      if (ua.includes('iPod')) return 'iPod';
      return 'iOS Device';
    }

    if (platform === 'android') {
      // Try to extract device name from UA
      const match = ua.match(/Android.*;\s([^)]+)\)/);
      return match ? match[1] : 'Android Device';
    }

    if (platform === 'macos') {
      return 'Mac';
    }

    if (platform === 'windows') {
      return 'Windows PC';
    }

    if (platform === 'linux') {
      return 'Linux PC';
    }

    return 'Unknown Device';
  }

  /**
   * Detect device platform
   */
  private detectPlatform(): DeviceInfo['platform'] {
    const ua = navigator.userAgent.toLowerCase();

    if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('ipod')) {
      return 'ios';
    }

    if (ua.includes('android')) {
      return 'android';
    }

    if (ua.includes('mac')) {
      return 'macos';
    }

    if (ua.includes('windows')) {
      return 'windows';
    }

    if (ua.includes('linux')) {
      return 'linux';
    }

    return 'unknown';
  }

  /**
   * Get platform display name
   */
  private getPlatformName(platform: DeviceInfo['platform']): string {
    switch (platform) {
      case 'ios':
        return 'iOS (iCloud Keychain)';
      case 'android':
        return 'Android (Google)';
      case 'macos':
        return 'macOS (iCloud Keychain)';
      case 'windows':
        return 'Windows (Microsoft)';
      case 'linux':
        return 'Linux';
      default:
        return 'Unknown';
    }
  }

  /**
   * Get formatted device list for display
   */
  async getDeviceListFormatted(): Promise<string> {
    const status = await this.getSyncStatus();

    if (status.devices.length === 0) {
      return 'No devices registered';
    }

    let output = `Your Devices (${status.devices.length}):\n\n`;

    status.devices.forEach((device, index) => {
      const lastActiveDiff = Date.now() - new Date(device.lastActive).getTime();
      const lastActiveStr = this.formatTimeDiff(lastActiveDiff);

      output += `${index + 1}. ${device.name}\n`;
      output += `   Platform: ${this.getPlatformName(device.platform)}\n`;
      output += `   Last active: ${lastActiveStr}\n`;
      output += `   ${!device.canRevoke ? '(Current device)' : ''}\n\n`;
    });

    return output;
  }

  /**
   * Format time difference for display
   */
  private formatTimeDiff(ms: number): string {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) {
      return `${days} day${days > 1 ? 's' : ''} ago`;
    }

    if (hours > 0) {
      return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    }

    if (minutes > 0) {
      return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    }

    return 'just now';
  }
}
