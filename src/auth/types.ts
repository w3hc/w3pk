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
  // 32-byte secret from the WebAuthn PRF extension, released by the
  // authenticator only during this user-verified assertion. Powers
  // persistent-session encryption; absent on non-PRF authenticators.
  prfOutput?: ArrayBuffer;
}

/** Client extension results consumed by w3pk (subset of the WebAuthn spec) */
export interface PrfExtensionResults {
  prf?: {
    enabled?: boolean;
    results?: {
      first?: ArrayBuffer;
    };
  };
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
  getClientExtensionResults(): PrfExtensionResults;
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
  getClientExtensionResults(): PrfExtensionResults;
}
