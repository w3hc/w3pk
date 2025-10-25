import { startRegistration } from "@simplewebauthn/browser";
import { RegistrationError } from "../core/errors";
import { assertUsername, assertEthereumAddress } from "../utils/validation";
import type { RegisterOptions } from "./types";
import { CredentialStorage } from "./storage";

function generateChallenge(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function generateUserId(username: string): string {
  const encoder = new TextEncoder();
  const data = encoder.encode(username + Date.now().toString());
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

export async function register(options: RegisterOptions): Promise<void> {
  try {
    const { username, ethereumAddress } = options;

    assertUsername(username);
    assertEthereumAddress(ethereumAddress);

    const storage = new CredentialStorage();

    if (storage.userExists(username)) {
      throw new Error("Username already registered");
    }

    const challenge = generateChallenge();
    const userId = generateUserId(username);

    const registrationOptions = {
      challenge,
      rp: {
        name: "w3pk",
        id: window.location.hostname,
      },
      user: {
        id: userId,
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
      userId,
      createdAt: Date.now(),
      lastUsed: Date.now(),
    });
  } catch (error) {
    throw new RegistrationError(
      error instanceof Error ? error.message : "Registration failed",
      error
    );
  }
}
