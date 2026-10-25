/**
 * WebAuthn PRF evaluation
 *
 * The PRF extension releases HMAC(credential secret, salt) only on a live,
 * user-verified assertion. The browser hashes each input as
 * SHA-256("WebAuthn PRF" || 0x00 || input) before it reaches the
 * authenticator, so inputs here can be any bytes.
 */

import { AuthenticationError, PrfUnsupportedError } from "../core/errors";
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
