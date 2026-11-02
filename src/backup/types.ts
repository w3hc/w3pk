/**
 * Backup and Recovery Type Definitions
 */

import type { Argon2idParams } from './encryption';

/**
 * - `file`: password backup file, restores without a passkey
 * - `qr`: QR backup, restores without a passkey
 * - `phrase`: recovery phrase written down
 * - `prf`: PRF backup from exportForSync(), restores only with the passkey
 */
export type BackupMethod = 'file' | 'qr' | 'phrase' | 'prf';

/** Backup methods that restore the wallet without a passkey */
export const PASSKEY_INDEPENDENT_METHODS: readonly BackupMethod[] = ['file', 'qr', 'phrase'];

export interface BackupStatus {
  /** A backup that restores without a passkey exists (file, QR or phrase) */
  hasBackup: boolean;
  /**
   * Next backup to make: `password` while no backup restores without a
   * passkey (it's the one that must exist), then `prf` for convenient sync
   * across devices where the passkey synced. Undefined once both exist.
   */
  recommendedMode?: 'password' | 'prf';
  evictionRisk: boolean;
  lastBackupAt?: string;
  methods: BackupMethod[];
  passkeySync: PasskeySyncStatus;
  recoveryPhrase: RecoveryPhraseStatus;
  securityScore: SecurityScore;
}

export interface PasskeySyncStatus {
  enabled: boolean;
  deviceCount: number;
  lastSyncTime?: string;
  platform: 'apple' | 'google' | 'microsoft' | 'unknown';
}

export interface RecoveryPhraseStatus {
  verified: boolean;
  verificationCount: number;
  lastVerified?: string;
  encryptedBackups: EncryptedBackupInfo[];
}

export interface EncryptedBackupInfo {
  id: string;
  method: 'qr' | 'file' | 'prf';
  location: string;
  createdAt: string;
  deviceFingerprint?: string;
}

export interface SecurityScore {
  total: number; // 0-100
  breakdown: {
    passkeyActive: number;
    passkeyMultiDevice: number;
    phraseVerified: number;
    encryptedBackup: number;
  };
  level: 'vulnerable' | 'protected' | 'secured' | 'fort-knox';
  nextMilestone: string;
}

export interface BackupMetadata {
  id: string;
  ethereumAddress: string;
  method: BackupMethod;
  createdAt: string;
  deviceFingerprint?: string;
  addressChecksum: string; // For verification
}

export const BACKUP_FILE_VERSION = 3;

/**
 * BackupFile v3 - acts like a "floppy disk"
 * Can be used to:
 * 1. Restore wallet with existing passkey (same or synced device)
 * 2. Register new passkey with this wallet (fresh device)
 * 3. Sync wallet across devices
 * 4. Split among guardians for social recovery
 *
 * It holds no address: the wallet's address comes from the decrypted mnemonic.
 */
export interface BackupFile {
  version: typeof BACKUP_FILE_VERSION;
  createdAt: string; // ISO 8601 timestamp
  // base64(iv || AES-256-GCM ciphertext), the key from Argon2id(password) or the passkey's PRF
  encryptedMnemonic: string;
  encryptionMethod: 'password' | 'prf';
  passwordEncryption?: PasswordEncryption;
  // Passkey that owned the wallet when the backup was made: lets a fresh
  // device where that passkey synced set up its metadata
  credential?: BackupCredential;
  // For PRF encryption: random per backup, the PRF is evaluated at
  // SHA-256("w3pk-prf-sync-v1" || prfSalt) with the passkey in `credential`
  prfSalt?: string;
  username?: string;
}

export interface PasswordEncryption extends Argon2idParams {
  kdf: 'argon2id';
  salt: string; // base64, 16 random bytes
}

export interface BackupCredential {
  id: string;
  publicKey: string;
}

export interface RecoveryScenario {
  type: 'lost-device' | 'lost-phrase' | 'lost-both' | 'switch-platform';
  description: string;
}

export interface SimulationResult {
  scenario: RecoveryScenario;
  success: boolean;
  availableMethods: RecoveryMethod[];
  timeEstimate: string;
  educationalNote: string;
}

export interface RecoveryMethod {
  method: string;
  success: boolean;
  time: string;
  requirements: string[];
}
