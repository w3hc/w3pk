/**
 * WebAuthn PRF evaluation
 *
 * The PRF extension releases HMAC(credential secret, salt) only on a live,
 * user-verified assertion. The browser hashes each input as
 * SHA-256("WebAuthn PRF" || 0x00 || input) before it reaches the
 * authenticator, so inputs here can be any bytes.
 */

import {
  AuthenticationError,
  CryptoError,
  PrfUnsupportedError,
} from "../core/errors";
import type { AuthenticationCredential } from "./types";
import { base64UrlToArrayBuffer } from "../utils/base64";
import { generateChallenge } from "../wallet/crypto";

export interface PrfEvaluation {
  /** 32-byte PRF output for `input` */
  output: ArrayBuffer;
  /** 32-byte PRF output for `second`, when asked for and returned */
  secondOutput?: ArrayBuffer;
  /** Credential the authenticator used */
  credentialId: string;
  assertion: AuthenticationCredential;
  /** Base64url challenge the assertion answers */
  challenge: string;
}

/**
 * Run a fresh user-verified assertion that evaluates the PRF at `input`.
 *
 * @param input - PRF input, evaluated as `prf.eval.first`
 * @param credentialId - Restrict the assertion to this credential;
 *   without it, the user picks any discoverable passkey for this RP
 * @param second - Optional second PRF input, evaluated as `prf.eval.second`
 *   in the same assertion
 * @throws PrfUnsupportedError when the authenticator returns no PRF output
 * @throws AuthenticationError when the assertion fails or is cancelled
 */
export async function evaluatePrf(
  input: BufferSource,
  credentialId?: string,
  second?: BufferSource
): Promise<PrfEvaluation> {
  let assertion: AuthenticationCredential;
  const challenge = generateChallenge();
  try {
    const options: PublicKeyCredentialRequestOptions = {
      challenge: base64UrlToArrayBuffer(challenge),
      rpId: window.location.hostname,
      // The PRF is only defined for user-verified assertions
      userVerification: "required",
      timeout: 60000,
      extensions: {
        prf: { eval: second ? { first: input, second } : { first: input } },
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
    assertion = credential;
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

  const results = assertion.getClientExtensionResults?.().prf?.results;
  const output = copyPrfResult(results?.first);
  if (!output) {
    throw new PrfUnsupportedError(assertion.id);
  }
  const secondOutput = second ? copyPrfResult(results?.second) : undefined;

  return { output, secondOutput, credentialId: assertion.id, assertion, challenge };
}

function copyPrfResult(result: BufferSource | undefined): ArrayBuffer | undefined {
  if (!result) return undefined;
  const copy = ArrayBuffer.isView(result)
    ? new Uint8Array(result.buffer, result.byteOffset, result.byteLength).slice().buffer
    : result.slice(0);
  return copy.byteLength === 32 ? copy : undefined;
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
 */
export async function derivePrfSecret(
  label: string,
  origin: string,
  tag: string,
  credentialId?: string
): Promise<PrfSecret> {
  const context = prfSecretContext(label, origin, tag);
  const input = await crypto.subtle.digest("SHA-256", context);
  const evaluation = await evaluatePrf(input, credentialId);

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
