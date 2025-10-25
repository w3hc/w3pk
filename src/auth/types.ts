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
}

// Re-export SimpleWebAuthn types for convenience
export type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from "@simplewebauthn/browser";
