import { startRegistration } from "@simplewebauthn/browser";
import { RegistrationError } from "../core/errors";
import { assertUsername, assertEthereumAddress } from "../utils/validation";
import type { RegisterOptions } from "./types";
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

export async function register(
  options: RegisterOptions
): Promise<{ signature: ArrayBuffer }> {
  try {
    const { username, ethereumAddress } = options;

    assertUsername(username);
    assertEthereumAddress(ethereumAddress);

    const storage = new CredentialStorage();

    if (storage.userExists(username)) {
      throw new Error("Username already registered");
    }

    const challenge = generateChallenge();

    const registrationOptions = {
      challenge,
      rp: {
        name: "w3pk",
        id: window.location.hostname,
      },
      user: {
        id: username,
        name: username,
        displayName: username,
      },
      pubKeyCredParams: [
        { type: "public-key" as const, alg: -7 },
        { type: "public-key" as const, alg: -257 },
      ],
      authenticatorSelection: {
        authenticatorAttachment: "platform" as const,
        userVerification: "required" as const,
        residentKey: "required" as const,
        requireResidentKey: true,
      },
      timeout: 60000,
      attestation: "none" as const,
    };

    const credential = await startRegistration({
      optionsJSON: registrationOptions,
    });
    const publicKey = credential.response.publicKey;

    if (!publicKey) {
      throw new Error("Public key not returned from authenticator");
    }

    storage.saveCredential({
      id: credential.id,
      publicKey,
      username,
      ethereumAddress,
      createdAt: Date.now(),
      lastUsed: Date.now(),
    });

    // Extract attestation signature for wallet encryption
    // The attestationObject contains the authenticator's signature
    console.log("[register] Credential response:", credential.response);
    const attestationObject = credential.response.attestationObject;
    console.log("[register] Attestation object:", attestationObject);

    if (!attestationObject) {
      throw new Error("Attestation object not returned from authenticator");
    }

    // Decode the attestationObject (it's base64url encoded CBOR)
    const attestationBuffer = base64UrlToArrayBuffer(attestationObject);
    console.log(
      "[register] Attestation buffer length:",
      attestationBuffer.byteLength
    );

    // For now, we'll use the raw attestation data as our signature material
    // This is cryptographically signed by the authenticator during registration
    return { signature: attestationBuffer };
  } catch (error) {
    throw new RegistrationError(
      error instanceof Error ? error.message : "Registration failed",
      error
    );
  }
}
