/**
 * WebAuthn PRF evaluation
 *
 * The PRF extension releases HMAC(credential secret, salt) only on a live,
 * user-verified assertion, and the output is only used once the assertion
 * passes login()'s checks. The browser hashes each input as
 * SHA-256("WebAuthn PRF" || 0x00 || input) before it reaches the
 * authenticator, so inputs here can be any bytes.
 */

import {
  AuthenticationError,
  CryptoError,
  PrfUnsupportedError,
  SyncRequiredError,
} from "../core/errors";
import type { AuthenticationCredential } from "./types";
import { assertPublicKeyMac, verifyPrfAssertion } from "./authenticate";
import { CredentialStorage, type StoredCredential } from "./storage";
import { base64UrlToArrayBuffer } from "../utils/base64";
import { generateChallenge, PRF_INPUT } from "../wallet/crypto";

export interface PrfCredential {
  id: string;
  /**
   * Base64url SPKI public key, already checked: against its MAC at login,
   * from the attestation at registration, or against a backup
   */
  publicKey: string;
}

export interface PrfOptions {
  /**
   * Restrict the assertion to this passkey and check its signature against
   * `credential.publicKey`. Without it, the user picks any discoverable
   * passkey for this RP, and the signature is checked against the passkey's
   * stored public key once that key's MAC checks out, with the PRF output at
   * `PRF_INPUT` evaluated as the second input of the same assertion.
   */
  credential?: PrfCredential;
  /** Second PRF input, evaluated as `prf.eval.second`; only with `credential` */
  second?: BufferSource;
  /** Thrown when the signature doesn't verify; AuthenticationError by default */
  signatureError?: () => Error;
}

export interface PrfEvaluation {
  /** 32-byte PRF output for `input` */
  output: ArrayBuffer;
  /** 32-byte PRF output for `second`, when asked for and returned */
  secondOutput?: ArrayBuffer;
  /** Credential the authenticator used */
  credentialId: string;
  /** The assertion, checked by verifyPrfAssertion(); its signature counter is not */
  assertion: AuthenticationCredential;
}

function wipe(buffer: ArrayBuffer | undefined): void {
  if (buffer) new Uint8Array(buffer).fill(0);
}

/**
 * Run a fresh user-verified assertion that evaluates the PRF at `input`, and
 * check it with verifyPrfAssertion(), as login() does, before any output is
 * returned.
 *
 * @param input - PRF input, evaluated as `prf.eval.first`
 * @throws PrfUnsupportedError when the authenticator returns no PRF output
 * @throws AuthenticationError when the assertion fails, is cancelled, comes
 *   from another passkey, isn't user-verified or its signature doesn't verify
 * @throws SyncRequiredError without `credential`, when the picked passkey has
 *   no metadata on this device
 */
export async function evaluatePrf(
  input: BufferSource,
  { credential, second, signatureError }: PrfOptions = {}
): Promise<PrfEvaluation> {
  if (second && !credential) {
    throw new CryptoError("A second PRF input needs a credential");
  }
  const challenge = generateChallenge();
  const assertion = await requestPrf(input, credential ? second : PRF_INPUT, challenge, credential?.id);

  let publicKey: string;
  let stored: StoredCredential | null = null;
  if (credential) {
    // WebAuthn L3 §7.2: the credential must be the one allowCredentials lists
    if (assertion.id !== credential.id) {
      throw new AuthenticationError("The assertion is from another passkey");
    }
    publicKey = credential.publicKey;
  } else {
    stored = await new CredentialStorage().getCredentialById(assertion.id);
    if (!stored) {
      throw new SyncRequiredError(assertion.id);
    }
    publicKey = stored.publicKey;
  }

  const { first: output, second: secondOutput } = await verifyPrfAssertion(
    assertion,
    publicKey,
    challenge,
    "required",
    signatureError
  );
  if (!output) {
    wipe(secondOutput);
    throw new PrfUnsupportedError(assertion.id);
  }

  if (stored) {
    try {
      await assertPublicKeyMac(secondOutput, stored);
    } catch (error) {
      wipe(output);
      throw error;
    } finally {
      wipe(secondOutput);
    }
    return { output, credentialId: assertion.id, assertion };
  }

  return {
    output,
    secondOutput: second ? secondOutput : undefined,
    credentialId: assertion.id,
    assertion,
  };
}

async function requestPrf(
  first: BufferSource,
  second: BufferSource | undefined,
  challenge: string,
  credentialId: string | undefined
): Promise<AuthenticationCredential> {
  try {
    const options: PublicKeyCredentialRequestOptions = {
      challenge: base64UrlToArrayBuffer(challenge),
      rpId: window.location.hostname,
      // The PRF is only defined for user-verified assertions
      userVerification: "required",
      timeout: 60000,
      extensions: {
        prf: { eval: second ? { first, second } : { first } },
      } as AuthenticationExtensionsClientInputs,
    };

    if (credentialId) {
      options.allowCredentials = [{
        id: base64UrlToArrayBuffer(credentialId),
        type: "public-key",
        transports: ["internal", "hybrid", "usb", "nfc", "ble"],
      }];
    }

    const credential = await navigator.credentials.get({
      publicKey: options,
    }) as AuthenticationCredential | null;

    if (!credential) {
      throw new AuthenticationError("Authentication failed - no credential returned");
    }
    return credential;
  } catch (error: any) {
    if (error instanceof AuthenticationError) throw error;
    if (error?.name === "NotAllowedError") {
      throw new AuthenticationError(
        "Authentication was cancelled or the passkey is not available on this device.",
        error
      );
    }
    throw new AuthenticationError(
      `Passkey authentication failed: ${error instanceof Error ? error.message : "Unknown error"}`,
      error
    );
  }
}

export interface PrfSecret {
  /** 32-byte secret for this origin and tag */
  secret: Uint8Array;
  /** Credential the secret is bound to; a new credential gives a new secret */
  credentialId: string;
}

export const PRF_SECRET_LABEL = "w3pk-prf-v1";
const PRF_SECRET_HKDF_SALT = new TextEncoder().encode("w3pk-prf-secret-v1");

export function assertPrfSecretTag(tag: string): void {
  if (typeof tag !== "string" || tag.length === 0 || tag.includes(":")) {
    throw new CryptoError("PRF secret tag must be a non-empty string without ':'");
  }
}

function prfSecretContext(label: string, origin: string, tag: string): Uint8Array<ArrayBuffer> {
  if (label.length === 0 || label.includes(":")) {
    throw new CryptoError("PRF secret label must be a non-empty string without ':'");
  }
  assertPrfSecretTag(tag);
  return new TextEncoder().encode(`${label}:${origin}:${tag}`);
}

/**
 * Derive a 32-byte secret for `origin` and `tag` from a fresh PRF evaluation.
 *
 * PRF input: SHA-256(label + ":" + origin + ":" + tag).
 * Secret: HKDF-SHA256(PRF output, fixed salt, info = the same context), 32 bytes.
 * Tags can't contain ':' so no origin/tag pair collides with another.
 * The public API always uses `PRF_SECRET_LABEL`; secrets w3pk keeps to itself
 * use their own label, which no public tag can reach.
 *
 * @param credential - The logged-in passkey; see evaluatePrf()
 */
export async function derivePrfSecret(
  label: string,
  origin: string,
  tag: string,
  credential?: PrfCredential
): Promise<PrfSecret> {
  const context = prfSecretContext(label, origin, tag);
  const input = await crypto.subtle.digest("SHA-256", context);
  const evaluation = await evaluatePrf(input, { credential });

  try {
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      evaluation.output,
      "HKDF",
      false,
      ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: PRF_SECRET_HKDF_SALT, info: context },
      keyMaterial,
      256
    );
    return { secret: new Uint8Array(bits), credentialId: evaluation.credentialId };
  } catch (error) {
    throw new CryptoError("Failed to derive secret from PRF output", error);
  } finally {
    new Uint8Array(evaluation.output).fill(0);
  }
}
