import { AuthenticationError } from "../core/errors";
import type { AuthResult, AuthenticationCredential } from "./types";
import type { StoredCredential } from "./storage";
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
      userVerification: "required",
      timeout: 60000,
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
      // Passkey authenticated successfully but metadata not found locally
      // This happens when using a cloud-synced passkey on a new device
      throw new AuthenticationError(
        "Passkey authenticated but wallet data not found on this device. To sync your account: 1) Select your passkey when prompted, then 2) Provide your backup file. This allows you to use the same passkey on multiple devices."
      );
    }

    const isValid = await verifyAssertion(assertion, credential, storage);

    if (!isValid) {
      throw new Error("Signature verification failed");
    }

    return {
      verified: true,
      user: {
        username: credential.username,
        ethereumAddress: credential.ethereumAddress,
        credentialId: credential.id,
      },
      signature: assertion.response.signature,
    };
  } catch (error) {
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
    const authenticatorData = assertion.response.authenticatorData;
    const authDataView = new DataView(authenticatorData);
    const authDataBytes = new Uint8Array(authenticatorData);

    // 1. Verify RP ID hash (first 32 bytes of authenticator data)
    const rpIdHash = authDataBytes.slice(0, 32);
    const expectedRpId = window.location.hostname;
    const expectedHash = new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode(expectedRpId))
    );

    // Compare RP ID hashes
    if (!arrayEquals(rpIdHash, expectedHash)) {
      console.error("RP ID hash mismatch - possible phishing attack");
      return false;
    }

    // 2. Extract and verify signature counter (bytes 33-36, big-endian)
    const signCount = authDataView.getUint32(33, false);

    // Verify signature counter to detect cloned authenticators
    // Counter should always increase (or be 0 if authenticator doesn't support counters)
    if (signCount > 0 || (credential.signCount && credential.signCount > 0)) {
      const storedCount = credential.signCount || 0;
      if (signCount <= storedCount) {
        console.error(
          `Authenticator cloning detected! Counter did not increase: stored=${storedCount}, received=${signCount}`
        );
        return false;
      }
    }

    // 3. Verify the signature
    const publicKeyBuffer = base64UrlToArrayBuffer(credential.publicKey);
    const publicKey = await crypto.subtle.importKey(
      "spki",
      publicKeyBuffer,
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      false,
      ["verify"]
    );

    const clientDataJSON = assertion.response.clientDataJSON;
    const clientDataHash = await crypto.subtle.digest(
      "SHA-256",
      clientDataJSON
    );

    const signedData = new Uint8Array(
      authenticatorData.byteLength + clientDataHash.byteLength
    );
    signedData.set(new Uint8Array(authenticatorData), 0);
    signedData.set(
      new Uint8Array(clientDataHash),
      authenticatorData.byteLength
    );

    const signature = assertion.response.signature;
    const rawSignature = derToRaw(new Uint8Array(signature));

    const isValid = await crypto.subtle.verify(
      {
        name: "ECDSA",
        hash: "SHA-256",
      },
      publicKey,
      rawSignature,
      signedData
    );

    if (!isValid) {
      return false;
    }

    // 4. Update signature counter in storage
    await storage.updateSignatureCounter(credential.id, signCount);

    return true;
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
