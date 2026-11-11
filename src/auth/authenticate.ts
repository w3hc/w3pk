import {
  AuthenticationError,
  SyncRequiredError,
  Web3PasskeyError,
  type SyncBootstrapReason,
} from "../core/errors";
import type { AuthResult, AuthenticationCredential } from "./types";
import type { StoredCredential } from "./storage";
import { CredentialStorage } from "./storage";
import {
  arrayBufferToBase64Url,
  base64UrlToArrayBuffer,
} from "../utils/base64";
import { generateChallenge, PRF_INPUT, verifyPublicKeyMac } from "../wallet/crypto";
import { isUserPresent, isUserVerified } from "./flags";
import { parseDerSignature } from "../utils/crypto";

/**
 * @param credentialId - Offer only this passkey; without it, every passkey
 *   with metadata on this device
 */
export async function login(
  userVerification: UserVerificationRequirement = "required",
  credentialId?: string
): Promise<AuthResult> {
  try {
    const storage = new CredentialStorage();
    const challenge = generateChallenge();

    let allowCredentials: Array<{ id: string; type: "public-key"; transports?: AuthenticatorTransport[] }> = [];

    try {
      const ids = credentialId
        ? [credentialId]
        : (await storage.getAllCredentials()).map(cred => cred.id);
      allowCredentials = ids.map(id => ({
        id,
        type: "public-key" as const,
        transports: ["internal", "hybrid", "usb", "nfc", "ble"] as AuthenticatorTransport[],
      }));
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

    // Authenticator-held secret released by this assertion. Undefined on
    // authenticators without PRF support, and dropped when an assertion that
    // didn't require UV wasn't user-verified (it would be a different
    // secret) — persistent sessions are then disabled (in-memory sessions
    // still work).
    const { first: prfOutput } = await verifyPrfAssertion(assertion, {
      publicKey: credential.publicKey,
      challenge,
      userVerification,
    });

    if (!(await verifySignCount(assertion, credential, storage))) {
      throw new Error("Signature counter did not increase");
    }

    return {
      verified: true,
      user: {
        username: credential.username,
        ethereumAddress: credential.ethereumAddress,
        credentialId: credential.id,
      },
      credential,
      signature: assertion.response.signature,
      prfOutput,
      userVerified: isUserVerified(new Uint8Array(assertion.response.authenticatorData)),
    };
  } catch (error) {
    if (error instanceof Web3PasskeyError) throw error;
    throw new AuthenticationError(
      error instanceof Error ? error.message : "Authentication failed",
      error
    );
  }
}

export interface PrfResults {
  first?: ArrayBuffer;
  second?: ArrayBuffer;
}

export type AssertionMismatch = Extract<SyncBootstrapReason, "CREDENTIAL_MISMATCH" | "PUBLIC_KEY_MISMATCH">;

export interface PrfAssertionCheck {
  /** Base64url SPKI the signature must verify against */
  publicKey: string;
  /** The base64url challenge sent in the request options */
  challenge: string;
  userVerification: UserVerificationRequirement;
  /** The credential the request's allowCredentials listed, if any */
  credentialId?: string;
  /** The error for an assertion from another passkey or with a signature that doesn't verify */
  mismatchError?: (reason: AssertionMismatch, credentialId: string) => Error;
}

function defaultMismatchError(reason: AssertionMismatch): Error {
  return new AuthenticationError(
    reason === "CREDENTIAL_MISMATCH"
      ? "The assertion is from another passkey"
      : "Signature verification failed"
  );
}

/**
 * Check an assertion that evaluated the PRF as login() does, and return its
 * PRF outputs (WebAuthn L3 §7.2): the credential the request allowed,
 * verifyAssertionSignature() against `publicKey`, then the UV flag, which
 * must be set when `userVerification` is "required". Without UV,
 * hmac-secret evaluates the credential's other PRF (§10.1.4), so the
 * outputs are dropped. Outputs that aren't 32 bytes are dropped too. The
 * outputs are taken out of the assertion either way (see takePrfResults()).
 *
 * @throws `mismatchError()` (AuthenticationError by default) when the
 *   assertion is from another passkey or its signature doesn't verify
 * @throws AuthenticationError when UV is required and not set
 */
export async function verifyPrfAssertion(
  assertion: AuthenticationCredential,
  { publicKey, challenge, userVerification, credentialId, mismatchError = defaultMismatchError }: PrfAssertionCheck
): Promise<PrfResults> {
  const results = takePrfResults(assertion);
  const discard = () => {
    wipeBuffer(results.first);
    wipeBuffer(results.second);
  };
  if (credentialId && assertion.id !== credentialId) {
    discard();
    throw mismatchError("CREDENTIAL_MISMATCH", assertion.id);
  }
  if (!(await verifyAssertionSignature(assertion, publicKey, challenge))) {
    discard();
    throw mismatchError("PUBLIC_KEY_MISMATCH", assertion.id);
  }
  if (!isUserVerified(new Uint8Array(assertion.response.authenticatorData))) {
    discard();
    if (userVerification === "required") {
      throw new AuthenticationError("User verification flag not set");
    }
    return {};
  }
  return results;
}

/**
 * Take an assertion's PRF outputs out of its client extension results:
 * copies of the 32-byte ones, the originals zeroed
 */
export function takePrfResults(assertion: AuthenticationCredential): PrfResults {
  const results = assertion.getClientExtensionResults?.().prf?.results;
  return { first: takePrfResult(results?.first), second: takePrfResult(results?.second) };
}

/** A copy of a 32-byte PRF output, or undefined for any other length. The original is zeroed. */
export function takePrfResult(result: BufferSource | undefined): ArrayBuffer | undefined {
  if (!result) return undefined;
  const bytes = ArrayBuffer.isView(result)
    ? new Uint8Array(result.buffer, result.byteOffset, result.byteLength)
    : new Uint8Array(result);
  const copy = bytes.slice().buffer;
  bytes.fill(0);
  return copy.byteLength === 32 ? copy : undefined;
}

export function wipeBuffer(buffer: ArrayBuffer | undefined): void {
  if (buffer) new Uint8Array(buffer).fill(0);
}

/**
 * Check the signature counter as login() does: it detects cloned
 * authenticators, so it must increase unless the authenticator keeps none.
 * Saves the new counter.
 */
export async function verifySignCount(
  assertion: AuthenticationCredential,
  credential: StoredCredential,
  storage: CredentialStorage
): Promise<boolean> {
  try {
    // Bytes 33-36 of authenticator data, big-endian
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
    console.error("Signature counter error:", error);
    return false;
  }
}

/**
 * Check a stored passkey's public key against its MAC, keyed from the PRF
 * output at `PRF_INPUT` (see macPublicKey)
 *
 * @throws AuthenticationError when there is no PRF output or the MAC doesn't match
 */
export async function assertPublicKeyMac(
  prfOutput: BufferSource | undefined,
  credential: StoredCredential
): Promise<void> {
  if (
    !prfOutput ||
    !(await verifyPublicKeyMac(prfOutput, credential.id, credential.publicKey, credential.publicKeyMac))
  ) {
    throw new AuthenticationError("The passkey's stored public key failed authentication");
  }
}

/**
 * Check an assertion against `publicKey` (base64url SPKI, P-256): its client
 * data (type `webauthn.get`, `challenge`, this page's origin), its RP ID hash,
 * the user-presence flag and its signature. The signature counter and the
 * user-verification flag are not checked: see verifyPrfAssertion().
 *
 * @param challenge - The base64url challenge sent in the request options
 */
export async function verifyAssertionSignature(
  assertion: AuthenticationCredential,
  publicKey: string,
  challenge: string
): Promise<boolean> {
  try {
    if (!verifyClientData(assertion.response.clientDataJSON, challenge, "webauthn.get")) {
      return false;
    }

    const authenticatorData = assertion.response.authenticatorData;
    const authDataBytes = new Uint8Array(authenticatorData);

    if (!isUserPresent(authDataBytes)) {
      console.error("User presence flag not set");
      return false;
    }

    if (!(await verifyRpIdHash(authDataBytes))) {
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

/**
 * Check `clientDataJSON` per WebAuthn L3 §7.1 and §7.2: its type, the
 * base64url `challenge` sent in the options, and this page's exact origin.
 */
export function verifyClientData(
  clientDataJSON: ArrayBuffer,
  challenge: string,
  type: "webauthn.create" | "webauthn.get"
): boolean {
  let clientData: { type?: unknown; challenge?: unknown; origin?: unknown };
  try {
    clientData = JSON.parse(new TextDecoder().decode(clientDataJSON));
  } catch {
    console.error("Invalid clientDataJSON");
    return false;
  }
  if (clientData?.type !== type) {
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
 * Check that authenticator data's RP ID hash is the SHA-256 of this page's
 * hostname, the RP ID w3pk sends.
 */
export async function verifyRpIdHash(authData: Uint8Array): Promise<boolean> {
  const expectedHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(window.location.hostname))
  );
  if (!arrayEquals(authData.slice(0, 32), expectedHash)) {
    console.error("RP ID hash mismatch - possible phishing attack");
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
