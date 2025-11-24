/**
 * Authentication-related types
 */

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

/**
 * Native WebAuthn credential response (registration)
 */
export interface RegistrationCredential {
  id: string;
  rawId: ArrayBuffer;
  type: 'public-key';
  response: {
    clientDataJSON: ArrayBuffer;
    attestationObject: ArrayBuffer;
    publicKey?: ArrayBuffer;
    publicKeyAlgorithm?: number;
  };
}

/**
 * Native WebAuthn credential response (authentication)
 */
export interface AuthenticationCredential {
  id: string;
  rawId: ArrayBuffer;
  type: 'public-key';
  response: {
    clientDataJSON: ArrayBuffer;
    authenticatorData: ArrayBuffer;
    signature: ArrayBuffer;
    userHandle?: ArrayBuffer;
  };
}
