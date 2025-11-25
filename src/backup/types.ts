/**
 * Backup and Recovery Type Definitions
 */

export interface BackupStatus {
  passkeySync: PasskeySyncStatus;
  recoveryPhrase: RecoveryPhraseStatus;
  socialRecovery?: SocialRecoveryStatus;
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
  method: 'zip' | 'qr' | 'file';
  location: string;
  createdAt: string;
  deviceFingerprint?: string;
}

export interface SocialRecoveryStatus {
  enabled: boolean;
  guardians: Guardian[];
  threshold: number;
  sharesDistributed: number;
  verifiedGuardians: number;
}

export interface Guardian {
  id: string;
  name: string;
  email?: string;
  publicKey?: string;
  shareEncrypted: string;
  status: 'pending' | 'active' | 'revoked';
  addedAt: string;
  lastVerified?: string;
}

export interface SecurityScore {
  total: number; // 0-100
  breakdown: {
    passkeyActive: number;
    passkeyMultiDevice: number;
    phraseVerified: number;
    encryptedBackup: number;
    socialRecovery: number;
  };
  level: 'vulnerable' | 'protected' | 'secured' | 'fort-knox';
  nextMilestone: string;
}

export interface BackupMetadata {
  id: string;
  ethereumAddress: string;
  method: 'zip' | 'qr' | 'file';
  createdAt: string;
  deviceFingerprint?: string;
  addressChecksum: string; // For verification
}

/**
 * Simplified backup file format - acts like a "floppy disk"
 * Can be used to:
 * 1. Restore wallet with existing passkey (same or synced device)
 * 2. Register new passkey with this wallet (fresh device)
 * 3. Sync wallet across devices
 * 4. Split among guardians for social recovery
 */
export interface BackupFile {
  createdAt: string; // ISO 8601 timestamp
  ethereumAddress: string; // m/44'/60'/0'/0/0 address (index #0)
  encryptedMnemonic: string; // AES-256-GCM encrypted with passkey-derived key OR password
  encryptionMethod: 'passkey' | 'password' | 'hybrid';
  // For passkey encryption (optional, used when encryptionMethod is 'passkey' or 'hybrid')
  credentialId?: string;
  publicKeyFingerprint?: string; // SHA-256 hash of public key for identification
  // For password encryption (optional, used when encryptionMethod is 'password' or 'hybrid')
  passwordEncryption?: {
    salt: string;
    iv: string;
    iterations: number;
  };
  // Metadata for verification
  addressChecksum: string; // For verification after decryption
}

export interface EncryptedBackupData {
  version: number;
  encryptedMnemonic: string;
  salt: string;
  iterations: number;
  metadata: BackupMetadata;
  verification: {
    addressChecksum: string;
  };
}

export interface ZipBackupOptions {
  password: string;
  includeInstructions?: boolean;
  deviceBinding?: boolean;
}

export interface QRBackupOptions {
  password?: string;
  errorCorrection?: 'L' | 'M' | 'Q' | 'H';
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
