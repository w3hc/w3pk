/**
 * Authentication-related types
 */

import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from "@simplewebauthn/browser";

export interface RegisterOptions {
  username: string;
  ethereumAddress: string;
}

export interface AuthResult {
  verified: boolean;
  user?: {
    username: string;
    ethereumAddress: string;
    credentialId: string;
  };
  // SECURITY: Signature is needed to derive encryption keys
  // This ensures keys can only be derived after biometric/PIN authentication
  signature?: ArrayBuffer;
}

// Re-export SimpleWebAuthn types for convenience
export type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from "@simplewebauthn/browser";
