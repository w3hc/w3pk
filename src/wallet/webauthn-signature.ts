import { AbiCoder, getBytes, hexlify } from "ethers";
import { WalletError } from "../core/errors";
import { base64UrlDecode } from "../utils/base64";
import { extractRS } from "../utils/crypto";

/** Raw output of a WebAuthn assertion */
export interface WebAuthnAssertion {
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  /** DER-encoded P-256 signature */
  signature: Uint8Array;
}

/**
 * Encodes an assertion as the `W3pkAccount` signature:
 * `abi.encode(r, s, challengeIndex, typeIndex, authenticatorData, clientDataJSON)`,
 * with `s` normalized to the lower half of the curve order
 *
 * @throws WalletError if `clientDataJSON` has no `type` or `challenge` field
 */
export function encodeWebAuthnSignature(assertion: WebAuthnAssertion): string {
  const clientDataJSON = new TextDecoder().decode(assertion.clientDataJSON);
  const challengeIndex = clientDataJSON.indexOf('"challenge":"');
  const typeIndex = clientDataJSON.indexOf('"type":"webauthn.get"');
  if (challengeIndex < 0 || typeIndex < 0) {
    throw new WalletError("Invalid clientDataJSON: missing type or challenge");
  }
  const { r, s } = extractRS(assertion.signature);
  return AbiCoder.defaultAbiCoder().encode(
    ["bytes32", "bytes32", "uint256", "uint256", "bytes", "string"],
    [r, s, challengeIndex, typeIndex, hexlify(assertion.authenticatorData), clientDataJSON]
  );
}

/**
 * Asks the passkey for a user-verified assertion over a 32-byte challenge
 *
 * @param challenge - 0x-prefixed 32-byte hash
 * @param credentialId - Credential ID (base64url encoded)
 */
export async function getWebAuthnAssertion(
  challenge: string,
  credentialId: string
): Promise<WebAuthnAssertion> {
  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: new Uint8Array(getBytes(challenge)),
      rpId: window.location.hostname,
      allowCredentials: [{ id: base64UrlDecode(credentialId), type: "public-key" }],
      userVerification: "required",
      timeout: 60000,
    },
  })) as PublicKeyCredential | null;

  if (!credential?.response) {
    throw new WalletError("WebAuthn signature failed");
  }
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    authenticatorData: new Uint8Array(response.authenticatorData),
    clientDataJSON: new Uint8Array(response.clientDataJSON),
    signature: new Uint8Array(response.signature),
  };
}

/**
 * Signs a 32-byte challenge with the passkey, encoded for `W3pkAccount`
 */
export async function signWithPasskey(challenge: string, credentialId: string): Promise<string> {
  return encodeWebAuthnSignature(await getWebAuthnAssertion(challenge, credentialId));
}

/**
 * A `W3pkAccount` signature of the length a real one has for `origin`, for gas
 * estimation: it fails validation without reverting
 */
export function stubWebAuthnSignature(origin: string): string {
  const stub = "0x" + "7f".repeat(32);
  const clientDataJSON = `{"type":"webauthn.get","challenge":"${"A".repeat(43)}","origin":"${origin}","crossOrigin":false}`;
  return AbiCoder.defaultAbiCoder().encode(
    ["bytes32", "bytes32", "uint256", "uint256", "bytes", "string"],
    [stub, stub, clientDataJSON.indexOf('"challenge":"'), 1, "0x" + "7f".repeat(32) + "05" + "00000000", clientDataJSON]
  );
}
