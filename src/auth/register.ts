import { RegistrationError } from "../core/errors";
import { assertUsername, assertEthereumAddress } from "../utils/validation";
import type { RegisterOptions, RegistrationCredential } from "./types";
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

/**
 * Extract the public key from WebAuthn attestation object
 * The public key is in COSE format, we need to extract it and convert to SPKI
 */
async function extractPublicKeyFromAttestation(
  attestationObject: ArrayBuffer
): Promise<string | null> {
  try {
    // Decode CBOR attestation object
    const attestationBuffer = new Uint8Array(attestationObject);

    // Parse CBOR to find authData
    const authDataOffset = findAuthDataOffset(attestationBuffer);
    if (authDataOffset === -1) return null;

    // AuthData structure:
    // - 32 bytes: RP ID hash
    // - 1 byte: flags
    // - 4 bytes: signature counter
    // - variable: attested credential data (if AT flag is set)

    const authData = attestationBuffer.slice(authDataOffset);
    const flags = authData[32];
    const attestedCredentialDataIncluded = (flags & 0x40) !== 0;

    if (!attestedCredentialDataIncluded) {
      return null;
    }

    // Skip: RP ID hash (32) + flags (1) + counter (4) = 37 bytes
    let offset = 37;

    // AAGUID: 16 bytes (skip)
    offset += 16;

    // Credential ID length: 2 bytes
    const credIdLength = (authData[offset] << 8) | authData[offset + 1];
    offset += 2;

    // Credential ID (skip)
    offset += credIdLength;

    // Credential public key in COSE format
    const cosePublicKey = authData.slice(offset);

    // Convert COSE to SPKI format
    const spkiKey = await coseToSpki(cosePublicKey);
    return arrayBufferToBase64Url(spkiKey);
  } catch (error) {
    console.error("Failed to extract public key:", error);
    return null;
  }
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

async function coseToSpki(coseKey: Uint8Array): Promise<ArrayBuffer> {
  // Parse COSE key (simplified for ES256 / P-256)
  // COSE format is CBOR map with keys:
  // 1: kty (2 = EC2)
  // 3: alg (-7 = ES256)
  // -1: crv (1 = P-256)
  // -2: x coordinate (32 bytes)
  // -3: y coordinate (32 bytes)

  // Find x and y coordinates in CBOR structure
  const x = extractCoseCoordinate(coseKey, -2);
  const y = extractCoseCoordinate(coseKey, -3);

  if (!x || !y) {
    throw new Error("Failed to extract EC coordinates from COSE key");
  }

  // Build uncompressed EC point: 0x04 || x || y
  const publicKeyBytes = new Uint8Array(65);
  publicKeyBytes[0] = 0x04; // Uncompressed point
  publicKeyBytes.set(x, 1);
  publicKeyBytes.set(y, 33);

  // Wrap in SPKI format for P-256
  // This is the DER-encoded SPKI structure for P-256 public keys
  const spkiPrefix = new Uint8Array([
    0x30, 0x59, // SEQUENCE, length 89
    0x30, 0x13, // SEQUENCE, length 19
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID: ecPublicKey
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID: P-256
    0x03, 0x42, 0x00, // BIT STRING, length 66
  ]);

  const spki = new Uint8Array(spkiPrefix.length + publicKeyBytes.length);
  spki.set(spkiPrefix, 0);
  spki.set(publicKeyBytes, spkiPrefix.length);

  return spki.buffer;
}

function extractCoseCoordinate(coseKey: Uint8Array, key: number): Uint8Array | null {
  // Look for the CBOR integer key (negative numbers are 0x20-0x3f range)
  const keyByte = key < 0 ? 0x20 + (-1 - key) : key;

  for (let i = 0; i < coseKey.length - 33; i++) {
    if (coseKey[i] === keyByte) {
      // Next byte should be 0x58 0x20 (byte string, length 32)
      if (coseKey[i + 1] === 0x58 && coseKey[i + 2] === 0x20) {
        return coseKey.slice(i + 3, i + 35);
      }
      // Or just 0x58 followed by length byte
      if (coseKey[i + 1] === 0x58) {
        const length = coseKey[i + 2];
        if (length === 32) {
          return coseKey.slice(i + 3, i + 35);
        }
      }
    }
  }

  return null;
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

    const challengeBuffer = base64UrlToArrayBuffer(challenge);
    const userIdBuffer = base64UrlToArrayBuffer(userIdBase64url);

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
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },  // ES256
        { type: "public-key", alg: -257 }, // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        userVerification: "required",
        residentKey: "required",
        requireResidentKey: true,
      },
      timeout: 60000,
      attestation: "none",
    };

    const credential = await navigator.credentials.create({
      publicKey: publicKeyCredentialCreationOptions,
    }) as RegistrationCredential | null;

    if (!credential) {
      throw new Error("Failed to create credential");
    }

    // Extract public key from attestation object
    const publicKey = await extractPublicKeyFromAttestation(credential.response.attestationObject);

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
      signCount: 0, // Initialize signature counter
    });

    console.log("[register] Credential response:", credential.response);
    const attestationObject = credential.response.attestationObject;
    console.log("[register] Attestation object length:", attestationObject.byteLength);

    return { signature: attestationObject };
  } catch (error) {
    throw new RegistrationError(
      error instanceof Error ? error.message : "Registration failed",
      error
    );
  }
}
