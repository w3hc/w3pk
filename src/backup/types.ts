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
  lastSyncTime?: number;
  platform: 'apple' | 'google' | 'microsoft' | 'unknown';
}

export interface RecoveryPhraseStatus {
  verified: boolean;
  verificationCount: number;
  lastVerified?: number;
  encryptedBackups: EncryptedBackupInfo[];
}

export interface EncryptedBackupInfo {
  id: string;
  method: 'zip' | 'qr' | 'file';
  location: string;
  createdAt: number;
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
  addedAt: number;
  lastVerified?: number;
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
  createdAt: number;
  deviceFingerprint?: string;
  addressChecksum: string; // For verification
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
