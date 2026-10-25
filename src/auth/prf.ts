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
  /** Credential the authenticator used */
  credentialId: string;
  assertion: AuthenticationCredential;
}

/**
 * Run a fresh user-verified assertion that evaluates the PRF at `input`.
 *
 * @param input - PRF input, evaluated as `prf.eval.first`
 * @param credentialId - Restrict the assertion to this credential;
 *   without it, the user picks any discoverable passkey for this RP
 * @throws PrfUnsupportedError when the authenticator returns no PRF output
 * @throws AuthenticationError when the assertion fails or is cancelled
 */
export async function evaluatePrf(
  input: BufferSource,
  credentialId?: string
): Promise<PrfEvaluation> {
  let assertion: AuthenticationCredential;
  try {
    const options: PublicKeyCredentialRequestOptions = {
      challenge: base64UrlToArrayBuffer(generateChallenge()),
      rpId: window.location.hostname,
      // The PRF is only defined for user-verified assertions
      userVerification: "required",
      timeout: 60000,
      extensions: {
        prf: { eval: { first: input } },
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

  const first = assertion.getClientExtensionResults?.().prf?.results?.first;
  if (!first) {
    throw new PrfUnsupportedError(assertion.id);
  }

  const output = ArrayBuffer.isView(first)
    ? new Uint8Array(first.buffer, first.byteOffset, first.byteLength).slice().buffer
    : first.slice(0);

  if (output.byteLength !== 32) {
    throw new PrfUnsupportedError(assertion.id);
  }

  return { output, credentialId: assertion.id, assertion };
}

export interface PrfSecret {
  /** 32-byte secret for this origin and tag */
  secret: Uint8Array;
  /** Credential the secret is bound to; a new credential gives a new secret */
  credentialId: string;
}

const PRF_SECRET_LABEL = "w3pk-prf-v1";
const PRF_SECRET_HKDF_SALT = new TextEncoder().encode("w3pk-prf-secret-v1");

function prfSecretContext(origin: string, tag: string): Uint8Array<ArrayBuffer> {
  if (typeof tag !== "string" || tag.length === 0 || tag.includes(":")) {
    throw new CryptoError("PRF secret tag must be a non-empty string without ':'");
  }
  return new TextEncoder().encode(`${PRF_SECRET_LABEL}:${origin}:${tag}`);
}

/**
 * Derive a 32-byte secret for `origin` and `tag` from a fresh PRF evaluation.
 *
 * PRF input: SHA-256("w3pk-prf-v1:" + origin + ":" + tag).
 * Secret: HKDF-SHA256(PRF output, fixed salt, info = the same context), 32 bytes.
 * Tags can't contain ':' so no origin/tag pair collides with another.
 */
export async function derivePrfSecret(
  origin: string,
  tag: string,
  credentialId?: string
): Promise<PrfSecret> {
  const context = prfSecretContext(origin, tag);
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
