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
  // PRF output from WebAuthn authenticator (32-byte secret)
  // Used for secure key derivation (fixes OPUS findings #1 and #3)
  prfOutput?: ArrayBuffer;
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
  getClientExtensionResults(): {
    prf?: {
      enabled?: boolean;
    };
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
  getClientExtensionResults(): {
    prf?: {
      results?: {
        first?: ArrayBuffer;
        second?: ArrayBuffer;
      };
    };
  };
}
