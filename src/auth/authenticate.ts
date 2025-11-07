import { startAuthentication } from "@simplewebauthn/browser";
import { AuthenticationError } from "../core/errors";
import type { AuthResult } from "./types";
import type { StoredCredential } from "./storage";
import { CredentialStorage } from "./storage";
import {
  arrayBufferToBase64Url,
  base64UrlToArrayBuffer,
  safeAtob,
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

    // Get all stored credentials to build allowCredentials list
    // This provides a hint to the browser about which credentials to look for
    // Helps when discoverable credentials aren't working properly
    let allowCredentials: Array<{ id: string; type: "public-key"; transports?: AuthenticatorTransport[] }> = [];

    try {
      const allCredentials = await storage.getAllCredentials();
      if (allCredentials.length > 0) {
        allowCredentials = allCredentials.map(cred => ({
          id: cred.id,
          type: "public-key" as const,
          // Include all possible transports to maximize compatibility
          transports: ["internal", "hybrid", "usb", "nfc", "ble"] as AuthenticatorTransport[],
        }));
        console.log(`[login] Found ${allowCredentials.length} stored credential(s)`);
      } else {
        console.log("[login] No stored credentials found, using discoverable credentials flow");
      }
    } catch (storageError) {
      console.warn("[login] Failed to retrieve stored credentials:", storageError);
      // Continue with empty allowCredentials (discoverable credentials flow)
    }

    const authOptions: any = {
      challenge,
      rpId: window.location.hostname,
      userVerification: "required" as const,
      timeout: 60000,
    };

    // Add allowCredentials if we have stored credentials
    // This helps browsers find the right credential even if discoverable credentials fail
    if (allowCredentials.length > 0) {
      authOptions.allowCredentials = allowCredentials;
    }

    let assertion;
    try {
      assertion = await startAuthentication({
        optionsJSON: authOptions,
      });
    } catch (error: any) {
      // Handle the specific case where no credentials are available
      if (error?.name === "NotAllowedError" ||
          error?.message?.toLowerCase().includes("no credentials available") ||
          error?.message?.toLowerCase().includes("no access key")) {

        // Check if we have credentials in storage but not in authenticator
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
      // Re-throw other errors
      throw error;
    }

    const credential = await storage.getCredentialById(assertion.id);

    if (!credential) {
      throw new Error("Credential not found in storage. This shouldn't happen - the passkey was authenticated but metadata is missing.");
    }

    const isValid = await verifyAssertion(assertion, credential);

    if (!isValid) {
      throw new Error("Signature verification failed");
    }

    await storage.updateLastUsed(credential.id);

    // SECURITY: Return the signature so it can be used to derive encryption keys
    // The signature can ONLY be obtained through biometric/PIN authentication
    const signatureBuffer = base64UrlToArrayBuffer(
      assertion.response.signature
    );

    return {
      verified: true,
      user: {
        username: credential.username,
        ethereumAddress: credential.ethereumAddress,
        credentialId: credential.id,
      },
      signature: signatureBuffer,
    };
  } catch (error) {
    throw new AuthenticationError(
      error instanceof Error ? error.message : "Authentication failed",
      error
    );
  }
}

async function verifyAssertion(
  assertion: any,
  credential: StoredCredential
): Promise<boolean> {
  try {
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

    const authenticatorData = base64UrlToArrayBuffer(
      assertion.response.authenticatorData
    );

    // clientDataJSON comes as base64url string, need to decode it first
    const clientDataJSON = assertion.response.clientDataJSON;
    let clientDataJSONString: string;

    // Check if it's already a JSON string or base64url encoded
    if (clientDataJSON.startsWith("eyJ")) {
      const decoded = safeAtob(clientDataJSON);
      clientDataJSONString = decoded;
    } else {
      // It's already a JSON string
      clientDataJSONString = clientDataJSON;
    }

    const clientDataHash = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(clientDataJSONString)
    );

    const signedData = new Uint8Array(
      authenticatorData.byteLength + clientDataHash.byteLength
    );
    signedData.set(new Uint8Array(authenticatorData), 0);
    signedData.set(
      new Uint8Array(clientDataHash),
      authenticatorData.byteLength
    );

    const signature = base64UrlToArrayBuffer(assertion.response.signature);
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

    return isValid;
  } catch (error) {
    console.error("Signature verification error:", error);
    return false;
  }
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
