import {
  AuthenticationError,
  SyncRequiredError,
  Web3PasskeyError,
} from "../core/errors";
import type { AuthResult, AuthenticationCredential } from "./types";
import type { StoredCredential } from "./storage";
import { CredentialStorage } from "./storage";
import {
  arrayBufferToBase64Url,
  base64UrlToArrayBuffer,
} from "../utils/base64";
import { generateChallenge, PRF_INPUT } from "../wallet/crypto";
import { isUserPresent, isUserVerified } from "./flags";
import { parseDerSignature } from "../utils/crypto";

export async function login(
  userVerification: UserVerificationRequirement = "required"
): Promise<AuthResult> {
  try {
    const storage = new CredentialStorage();
    const challenge = generateChallenge();

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
      // Silent fallback to discoverable credentials flow
    }

    const challengeBuffer = base64UrlToArrayBuffer(challenge);

    const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
      challenge: challengeBuffer,
      rpId: window.location.hostname,
      userVerification,
      timeout: 60000,
      // Evaluate the PRF with a FIXED input: the output is a deterministic
      // per-credential secret, so the session key derived at this login can
      // decrypt what the previous login encrypted.
      extensions: {
        prf: {
          eval: {
            first: PRF_INPUT,
          },
        },
      } as AuthenticationExtensionsClientInputs,
    };

    if (allowCredentials.length > 0) {
      publicKeyCredentialRequestOptions.allowCredentials = allowCredentials.map(cred => ({
        id: base64UrlToArrayBuffer(cred.id),
        type: cred.type,
        transports: cred.transports,
      }));
    }

    let assertion: AuthenticationCredential;
    try {
      const credential = await navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions,
      }) as AuthenticationCredential | null;

      if (!credential) {
        throw new Error("Authentication failed - no credential returned");
      }

      assertion = credential;
    } catch (error: any) {
      if (error?.name === "NotAllowedError" ||
          error?.message?.toLowerCase().includes("no credentials available") ||
          error?.message?.toLowerCase().includes("no access key")) {

        const storedCreds = await storage.getAllCredentials();
        if (storedCreds.length > 0) {
          throw new AuthenticationError(
            "Your passkey is not available on this device. You may need to restore your wallet from a backup, or login on the device where you registered."
          );
        } else {
          throw new AuthenticationError(
            "No passkey found. Please register first or restore from a backup."
          );
        }
      }
      throw error;
    }

    const credential = await storage.getCredentialById(assertion.id);

    if (!credential) {
      // Cloud-synced passkey used on a device that has no metadata for it
      throw new SyncRequiredError(assertion.id);
    }

    const isValid = await verifyAssertion(assertion, credential, storage, challenge);

    if (!isValid) {
      throw new Error("Signature verification failed");
    }

    // Authenticator-held secret released by this assertion. Undefined on
    // authenticators without PRF support, and dropped when the assertion
    // wasn't user-verified (it would be a different secret) — persistent
    // sessions are then disabled (in-memory sessions still work).
    const prfOutput = isUserVerified(new Uint8Array(assertion.response.authenticatorData))
      ? assertion.getClientExtensionResults?.().prf?.results?.first
      : undefined;

    return {
      verified: true,
      user: {
        username: credential.username,
        ethereumAddress: credential.ethereumAddress,
        credentialId: credential.id,
      },
      signature: assertion.response.signature,
      prfOutput,
    };
  } catch (error) {
    if (error instanceof Web3PasskeyError) throw error;
    throw new AuthenticationError(
      error instanceof Error ? error.message : "Authentication failed",
      error
    );
  }
}

/**
 * Check an assertion as login() does: verifyAssertionSignature() against the
 * stored credential's public key, then the signature counter, which must
 * increase unless the authenticator keeps none. Saves the new counter.
 *
 * @param challenge - The base64url challenge sent in the request options
 */
export async function verifyAssertion(
  assertion: AuthenticationCredential,
  credential: StoredCredential,
  storage: CredentialStorage,
  challenge: string
): Promise<boolean> {
  try {
    if (!(await verifyAssertionSignature(assertion, credential.publicKey, challenge))) {
      return false;
    }

    // Signature counter (bytes 33-36, big-endian) detects cloned authenticators:
    // it should always increase, or stay 0 if the authenticator has no counter
    const signCount = new DataView(assertion.response.authenticatorData).getUint32(33, false);
    if (signCount > 0 || (credential.signCount && credential.signCount > 0)) {
      const storedCount = credential.signCount || 0;
      if (signCount <= storedCount) {
        console.error(
          `Authenticator cloning detected! Counter did not increase: stored=${storedCount}, received=${signCount}`
        );
        return false;
      }
    }

    await storage.updateSignatureCounter(credential.id, signCount);

    return true;
  } catch (error) {
    console.error("Signature verification error:", error);
    return false;
  }
}

/**
 * Check an assertion against `publicKey` (base64url SPKI, P-256): its client
 * data (type `webauthn.get`, `challenge`, this page's origin), its RP ID hash,
 * the user-presence flag and its signature. The signature counter and the
 * user-verification flag are not checked.
 *
 * @param challenge - The base64url challenge sent in the request options
 */
export async function verifyAssertionSignature(
  assertion: AuthenticationCredential,
  publicKey: string,
  challenge: string
): Promise<boolean> {
  try {
    if (!verifyClientData(assertion.response.clientDataJSON, challenge)) {
      return false;
    }

    const authenticatorData = assertion.response.authenticatorData;
    const authDataBytes = new Uint8Array(authenticatorData);

    if (!isUserPresent(authDataBytes)) {
      console.error("User presence flag not set");
      return false;
    }

    const rpIdHash = authDataBytes.slice(0, 32);
    const expectedHash = new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode(window.location.hostname))
    );
    if (!arrayEquals(rpIdHash, expectedHash)) {
      console.error("RP ID hash mismatch - possible phishing attack");
      return false;
    }

    const key = await crypto.subtle.importKey(
      "spki",
      base64UrlToArrayBuffer(publicKey),
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      false,
      ["verify"]
    );

    const clientDataHash = await crypto.subtle.digest(
      "SHA-256",
      assertion.response.clientDataJSON
    );

    const signedData = new Uint8Array(
      authenticatorData.byteLength + clientDataHash.byteLength
    );
    signedData.set(authDataBytes, 0);
    signedData.set(new Uint8Array(clientDataHash), authenticatorData.byteLength);

    const { r, s } = parseDerSignature(new Uint8Array(assertion.response.signature));
    const rawSignature = new Uint8Array(64);
    rawSignature.set(r, 0);
    rawSignature.set(s, 32);

    return await crypto.subtle.verify(
      {
        name: "ECDSA",
        hash: "SHA-256",
      },
      key,
      rawSignature,
      signedData
    );
  } catch (error) {
    console.error("Signature verification error:", error);
    return false;
  }
}

function verifyClientData(clientDataJSON: ArrayBuffer, challenge: string): boolean {
  let clientData: { type?: unknown; challenge?: unknown; origin?: unknown };
  try {
    clientData = JSON.parse(new TextDecoder().decode(clientDataJSON));
  } catch {
    console.error("Invalid clientDataJSON");
    return false;
  }
  if (clientData?.type !== "webauthn.get") {
    console.error("Unexpected clientDataJSON type");
    return false;
  }
  if (clientData.challenge !== challenge) {
    console.error("Challenge mismatch - possible replay");
    return false;
  }
  if (clientData.origin !== window.location.origin) {
    console.error("Origin mismatch - possible phishing attack");
    return false;
  }
  return true;
}

/**
 * Compare two Uint8Arrays for equality
 */
function arrayEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
