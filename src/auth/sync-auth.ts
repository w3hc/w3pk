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
import { generateChallenge, PRF_INPUT } from "../wallet/crypto";
import { isUserVerified } from "./flags";
import { validateUsername } from "../utils/validation";

export interface PasskeySelectionResult {
  credentialId: string;
  /** From a pre-0.11.1 passkey's user handle */
  username?: string;
  /** The selection assertion, unverified */
  assertion: AuthenticationCredential;
  /** Base64url challenge the assertion answers */
  challenge: string;
  /** PRF output at `PRF_INPUT`, the source of the wallet key; absent without PRF */
  prfOutput?: ArrayBuffer;
}

/**
 * Passkeys registered before 0.11.1 used the username as user handle; newer
 * ones use random bytes, which don't decode to a valid username.
 */
function usernameFromUserHandle(userHandle?: ArrayBuffer): string | undefined {
  if (!userHandle?.byteLength) return undefined;
  try {
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(userHandle);
    return validateUsername(decoded) ? decoded : undefined;
  } catch {
    return undefined;
  }
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
      extensions: {
        prf: { eval: { first: PRF_INPUT } },
      } as AuthenticationExtensionsClientInputs,
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
    const prfOutput = isUserVerified(new Uint8Array(credential.response.authenticatorData))
      ? credential.getClientExtensionResults?.().prf?.results?.first
      : undefined;
    const username = usernameFromUserHandle(credential.response.userHandle);

    return {
      credentialId,
      username,
      assertion: credential,
      challenge,
      prfOutput,
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
