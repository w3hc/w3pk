/**
 * Social Recovery Type Definitions
 */

export interface Guardian {
  id: string;
  name: string;
  email?: string;
  phone?: string;
  publicKey?: string; // For encrypting their share
  shareEncrypted: string;
  status: 'pending' | 'active' | 'revoked';
  addedAt: number;
  lastVerified?: number;
}

export interface GuardianInvite {
  guardianId: string;
  qrCode: string; // Data URL for QR code
  shareCode: string; // Text code for manual entry
  explainer: string; // Educational text
  link?: string; // Optional deep link
}

export interface SocialRecoveryConfig {
  threshold: number; // M in M-of-N
  totalGuardians: number; // N in M-of-N
  guardians: Guardian[];
  createdAt: number;
  ethereumAddress: string;
}

export interface RecoveryShare {
  guardianId: string;
  share: string;
  index: number; // 1-based index
}

export interface RecoveryProgress {
  collected: number;
  required: number;
  guardians: {
    id: string;
    name: string;
    hasProvided: boolean;
  }[];
  canRecover: boolean;
}
