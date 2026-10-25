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

export async function login(): Promise<AuthResult> {
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
      // PRF requires user verification; keep "required" or PRF output vanishes
      userVerification: "required",
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

    const isValid = await verifyAssertion(assertion, credential, storage);

    if (!isValid) {
      throw new Error("Signature verification failed");
    }

    // Authenticator-held secret released by this user-verified assertion.
    // Undefined on authenticators without PRF support — persistent sessions
    // are then disabled for this device (in-memory sessions still work).
    const prfOutput = assertion.getClientExtensionResults?.().prf?.results?.first;

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

async function verifyAssertion(
  assertion: AuthenticationCredential,
  credential: StoredCredential,
  storage: CredentialStorage
): Promise<boolean> {
  try {
    if (!(await verifyAssertionSignature(assertion, credential.publicKey))) {
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
 * Check an assertion's RP ID hash and its signature against `publicKey`
 * (base64url SPKI, P-256). The signature counter is not checked.
 */
export async function verifyAssertionSignature(
  assertion: AuthenticationCredential,
  publicKey: string
): Promise<boolean> {
  try {
    const authenticatorData = assertion.response.authenticatorData;
    const authDataBytes = new Uint8Array(authenticatorData);

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

    const rawSignature = derToRaw(new Uint8Array(assertion.response.signature));

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

function derToRaw(der: Uint8Array): ArrayBuffer {
  let offset = 2;

  offset++;
  let rLength = der[offset++];
  if (rLength > 32) {
    offset++;
    rLength--;
  }
  const r = der.slice(offset, offset + rLength);
  offset += rLength;

  offset++;
  let sLength = der[offset++];
  if (sLength > 32) {
    offset++;
    sLength--;
  }
  const s = der.slice(offset, offset + sLength);

  const raw = new Uint8Array(64);
  raw.set(r, 32 - r.length);
  raw.set(s, 64 - s.length);

  return raw.buffer;
}
