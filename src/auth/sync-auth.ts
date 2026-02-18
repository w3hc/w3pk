/**
 * Sync Authentication Helper
 * Handles passkey selection and authentication for cross-device sync scenarios
 */

import { AuthenticationError } from "../core/errors";
import type { AuthenticationCredential } from "./types";
import { CredentialStorage } from "./storage";
import {
  arrayBufferToBase64Url,
  base64UrlToArrayBuffer,
} from "../utils/base64";

function generateChallenge(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return arrayBufferToBase64Url(array);
}

export interface PasskeySelectionResult {
  credentialId: string;
  publicKey: string;
  ethereumAddress?: string; // May be undefined if credential is not in local storage yet
}

/**
 * Prompts the user to select a passkey/webauthn credential
 * This is used in the sync flow where the user needs to authenticate
 * with their existing passkey before applying a backup file
 *
 * Use case: User has passkey synced to new device via iCloud/Google Password Manager
 * but needs to restore wallet data from backup file
 */
export async function promptPasskeySelection(): Promise<PasskeySelectionResult> {
  try {
    const storage = new CredentialStorage();
    const challenge = generateChallenge();
    const challengeBuffer = base64UrlToArrayBuffer(challenge);

    // Try to get stored credentials for allowCredentials list
    let allowCredentials: Array<{ id: string; type: "public-key"; transports?: AuthenticatorTransport[] }> = [];

    try {
      const allCredentials = await storage.getAllCredentials();
      if (allCredentials.length > 0) {
        allowCredentials = allCredentials.map(cred => ({
          id: cred.id,
          type: "public-key" as const,
          transports: ["internal", "hybrid", "usb", "nfc", "ble"] as AuthenticatorTransport[],
        }));
      }
    } catch (storageError) {
      // Silent fallback - will use discoverable credentials flow
    }

    const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
      challenge: challengeBuffer,
      rpId: window.location.hostname,
      userVerification: "required",
      timeout: 120000, // Longer timeout for sync flow (2 minutes)
    };

    // Add allowCredentials if we have any stored credentials
    if (allowCredentials.length > 0) {
      publicKeyCredentialRequestOptions.allowCredentials = allowCredentials.map(cred => ({
        id: base64UrlToArrayBuffer(cred.id),
        type: cred.type,
        transports: cred.transports,
      }));
    }

    // Prompt user to select their passkey
    const credential = await navigator.credentials.get({
      publicKey: publicKeyCredentialRequestOptions,
    }) as AuthenticationCredential | null;

    if (!credential) {
      throw new AuthenticationError("No passkey selected. Please select a passkey to continue with sync.");
    }

    const credentialId = credential.id;

    // Try to get the stored credential metadata
    const storedCredential = await storage.getCredentialById(credentialId);

    if (!storedCredential) {
      // Passkey authenticated but not in local storage yet
      // This is expected in the sync scenario - the user has the passkey but not the wallet data
      return {
        credentialId,
        publicKey: "", // Will need to be derived or provided from backup
        ethereumAddress: undefined,
      };
    }

    // Passkey found in local storage
    return {
      credentialId,
      publicKey: storedCredential.publicKey,
      ethereumAddress: storedCredential.ethereumAddress,
    };
  } catch (error: any) {
    if (error?.name === "NotAllowedError") {
      throw new AuthenticationError(
        "Passkey selection was cancelled. Please try again and select your passkey."
      );
    }

    if (error instanceof AuthenticationError) {
      throw error;
    }

    throw new AuthenticationError(
      `Failed to select passkey: ${error instanceof Error ? error.message : "Unknown error"}`,
      error
    );
  }
}

/**
 * Authenticate with a specific passkey (for scenarios where we know which credential to use)
 * Returns the raw WebAuthn assertion for verification
 */
export async function authenticateWithPasskey(
  credentialId: string
): Promise<AuthenticationCredential> {
  try {
    const challenge = generateChallenge();
    const challengeBuffer = base64UrlToArrayBuffer(challenge);

    const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
      challenge: challengeBuffer,
      rpId: window.location.hostname,
      userVerification: "required",
      timeout: 60000,
      allowCredentials: [{
        id: base64UrlToArrayBuffer(credentialId),
        type: "public-key",
        transports: ["internal", "hybrid", "usb", "nfc", "ble"] as AuthenticatorTransport[],
      }],
    };

    const credential = await navigator.credentials.get({
      publicKey: publicKeyCredentialRequestOptions,
    }) as AuthenticationCredential | null;

    if (!credential) {
      throw new AuthenticationError("Authentication failed - no credential returned");
    }

    return credential;
  } catch (error: any) {
    if (error?.name === "NotAllowedError") {
      throw new AuthenticationError(
        "Authentication was cancelled or the passkey is not available on this device."
      );
    }

    throw new AuthenticationError(
      `Passkey authentication failed: ${error instanceof Error ? error.message : "Unknown error"}`,
      error
    );
  }
}
