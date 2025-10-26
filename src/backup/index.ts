/**
 * Backup and Recovery Module
 * Provides three-layer security: Passkey Sync, Encrypted Backups, Social Recovery
 */

export { BackupManager } from './manager';
export { BackupStorage } from './storage';
export { ZipBackupCreator } from './zip-backup';
export { QRBackupCreator } from './qr-backup';

export * from './types';
export * from './encryption';
