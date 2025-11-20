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

    if (await storage.userExists(username)) {
      throw new Error("Username already registered");
    }

    const challenge = generateChallenge();

    const encoder = new TextEncoder();
    const usernameBytes = encoder.encode(username);
    const userIdBase64url = arrayBufferToBase64Url(usernameBytes);

    const registrationOptions = {
      challenge,
      rp: {
        name: "w3pk",
        id: window.location.hostname,
      },
      user: {
        id: userIdBase64url,
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

    await storage.saveCredential({
      id: credential.id,
      publicKey,
      username,
      ethereumAddress,
      createdAt: new Date().toISOString(),
      lastUsed: new Date().toISOString(),
    });

    console.log("[register] Credential response:", credential.response);
    const attestationObject = credential.response.attestationObject;
    console.log("[register] Attestation object:", attestationObject);

    if (!attestationObject) {
      throw new Error("Attestation object not returned from authenticator");
    }

    const attestationBuffer = base64UrlToArrayBuffer(attestationObject);
    console.log(
      "[register] Attestation buffer length:",
      attestationBuffer.byteLength
    );

    return { signature: attestationBuffer };
  } catch (error) {
    throw new RegistrationError(
      error instanceof Error ? error.message : "Registration failed",
      error
    );
  }
}
