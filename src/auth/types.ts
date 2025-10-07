/**
 * Authentication-related types
 */

import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";

export interface RegisterOptions {
  username: string;
  ethereumAddress: string;
}

export interface RegisterBeginResponse {
  options: PublicKeyCredentialCreationOptionsJSON;
}

export interface RegisterCompleteRequest {
  ethereumAddress: string;
  response: RegistrationResponseJSON;
}

export interface AuthenticateBeginResponse {
  options: PublicKeyCredentialRequestOptionsJSON;
}

export interface AuthenticateCompleteRequest {
  ethereumAddress?: string;
  response: AuthenticationResponseJSON;
}

export interface AuthResult {
  verified: boolean;
  user?: {
    id: string;
    username: string;
    ethereumAddress: string;
  };
}
