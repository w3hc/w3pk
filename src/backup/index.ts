/**
 * Backup and Recovery Module
 * Provides three-layer security: Passkey Sync, Encrypted Backups, Social Recovery
 */

export { BackupManager } from './manager';
export { BackupStorage } from './storage';
export { QRBackupCreator } from './qr-backup';
export { BackupFileManager } from './backup-file';

export * from './types';
export * from './encryption';
