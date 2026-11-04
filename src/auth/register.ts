import { RegistrationError } from "../core/errors";
import { assertUsername, assertEthereumAddress } from "../utils/validation";
import type { RegisterOptions, RegistrationCredential } from "./types";
import { CredentialStorage } from "./storage";
import {
  arrayBufferToBase64Url,
  base64UrlToArrayBuffer,
} from "../utils/base64";
import { generateChallenge, PRF_INPUT } from "../wallet/crypto";
import { isUserPresent, isUserVerified } from "./flags";
import { verifyClientData, verifyRpIdHash } from "./authenticate";
import { credentialPublicKeyFromAuthData } from "./attestation";

function getAuthData(attestationObject: ArrayBuffer): Uint8Array | null {
  const attestationBuffer = new Uint8Array(attestationObject);
  const authDataOffset = findAuthDataOffset(attestationBuffer);
  if (authDataOffset === -1) return null;
  return attestationBuffer.slice(authDataOffset);
}

function findAuthDataOffset(buffer: Uint8Array): number {
  // Simple CBOR parser to find authData field
  // In attestation object, authData is typically the second field
  // Format: {fmt: "none", attStmt: {}, authData: <bytes>}

  // Look for authData key (0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a')
  const authDataKey = new Uint8Array([0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61]);

  for (let i = 0; i < buffer.length - authDataKey.length; i++) {
    let match = true;
    for (let j = 0; j < authDataKey.length; j++) {
      if (buffer[i + j] !== authDataKey[j]) {
        match = false;
        break;
      }
    }
    if (match) {
      // Found authData key, next byte indicates length
      const lengthIndicator = buffer[i + authDataKey.length];
      let dataStart = i + authDataKey.length + 1;

      // Handle different CBOR length encodings
      if (lengthIndicator >= 0x58 && lengthIndicator <= 0x5b) {
        // Length in next 1-8 bytes
        const extraBytes = lengthIndicator - 0x57;
        dataStart += extraBytes;
      }

      return dataStart;
    }
  }

  return -1;
}

export async function register(
  options: RegisterOptions
): Promise<{ credentialId: string; signature: ArrayBuffer; prfOutput?: ArrayBuffer }> {
  try {
    const { username, ethereumAddress, userVerification = "required" } = options;

    assertUsername(username);
    assertEthereumAddress(ethereumAddress);

    const storage = new CredentialStorage();

    if (await storage.userExists(username)) {
      throw new Error("Username already registered");
    }

    const challenge = generateChallenge();

    const challengeBuffer = base64UrlToArrayBuffer(challenge);
    // The user handle must not contain personal information (WebAuthn §14.6.1)
    const userIdBuffer = crypto.getRandomValues(new Uint8Array(32));

    const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
      challenge: challengeBuffer,
      rp: {
        name: "w3pk",
        id: window.location.hostname,
      },
      user: {
        id: userIdBuffer,
        name: username,
        displayName: username,
      },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: {
        userVerification,
        residentKey: "required",
        requireResidentKey: true,
      },
      timeout: 60000,
      attestation: "none",
      // Ask for a PRF evaluation at creation. Platforms that support it
      // return the secret immediately (persistent session available right
      // after registration); platforms that only evaluate on get() return
      // nothing here and the first login() provides it instead.
      extensions: {
        prf: {
          eval: {
            first: PRF_INPUT,
          },
        },
      } as AuthenticationExtensionsClientInputs,
    };

    const credential = await navigator.credentials.create({
      publicKey: publicKeyCredentialCreationOptions,
    }) as RegistrationCredential | null;

    if (!credential) {
      throw new Error("Failed to create credential");
    }

    const attestationObject = credential.response.attestationObject;

    // WebAuthn L3 §7.1: client data, RP ID hash and user presence
    if (!verifyClientData(credential.response.clientDataJSON, challenge, "webauthn.create")) {
      throw new Error("Invalid client data");
    }
    const authData = getAuthData(attestationObject);
    if (!authData || !(await verifyRpIdHash(authData))) {
      throw new Error("RP ID hash mismatch");
    }
    if (!isUserPresent(authData)) {
      throw new Error("User presence flag not set");
    }

    const publicKey = arrayBufferToBase64Url(await credentialPublicKeyFromAuthData(authData));

    await storage.saveCredential({
      id: credential.id,
      publicKey,
      username,
      ethereumAddress,
      createdAt: new Date().toISOString(),
      lastUsed: new Date().toISOString(),
      signCount: 0, // Initialize signature counter
    });

    const prfOutput = isUserVerified(authData)
      ? credential.getClientExtensionResults?.().prf?.results?.first
      : undefined;

    return { credentialId: credential.id, signature: attestationObject, prfOutput };
  } catch (error) {
    throw new RegistrationError(
      error instanceof Error ? error.message : "Registration failed",
      error
    );
  }
}
