import { PrfUnsupportedError, RegistrationError } from "../core/errors";
import { assertUsername, assertEthereumAddress } from "../utils/validation";
import type { RegisterOptions, RegistrationCredential } from "./types";
import { CredentialStorage } from "./storage";
import {
  arrayBufferToBase64Url,
  base64UrlToArrayBuffer,
} from "../utils/base64";
import { generateChallenge, macPublicKey, PRF_INPUT } from "../wallet/crypto";
import { isUserPresent, isUserVerified } from "./flags";
import { verifyClientData, verifyRpIdHash } from "./authenticate";
import { authDataFromAttestationObject, credentialPublicKeyFromAuthData } from "./attestation";
import { copyPrfResult, evaluatePrf } from "./prf";

/**
 * Asks the authenticator to drop a passkey that was created but not stored
 * (WebAuthn L3 §5.1.10.2), so it does not linger as an orphan.
 */
function signalUnknownCredential(rpId: string, credentialId: string): void {
  if (typeof PublicKeyCredential === "undefined" || typeof PublicKeyCredential.signalUnknownCredential !== "function") {
    return;
  }
  PublicKeyCredential.signalUnknownCredential({ rpId, credentialId }).catch(() => {});
}

export async function register(
  options: RegisterOptions
): Promise<{
  credentialId: string;
  publicKey: string;
  signature: ArrayBuffer;
  prfOutput: ArrayBuffer;
}> {
  let unstored: { rpId: string; credentialId: string } | null = null;
  try {
    const { username, ethereumAddress, userVerification = "required" } = options;

    assertUsername(username);
    assertEthereumAddress(ethereumAddress);

    const storage = new CredentialStorage();

    if (await storage.userExists(username)) {
      throw new Error("Username already registered");
    }

    const challenge = generateChallenge();
    const rpId = window.location.hostname;

    const challengeBuffer = base64UrlToArrayBuffer(challenge);
    // The user handle must not contain personal information (WebAuthn §14.6.1)
    const userIdBuffer = crypto.getRandomValues(new Uint8Array(32));

    const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
      challenge: challengeBuffer,
      rp: {
        name: "w3pk",
        id: rpId,
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
      // Platforms that only evaluate the PRF on get() return nothing here,
      // and one assertion right after creation provides it instead
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
    unstored = { rpId, credentialId: credential.id };

    const attestationObject = credential.response.attestationObject;

    // WebAuthn L3 §7.1: client data, RP ID hash and user presence
    if (!verifyClientData(credential.response.clientDataJSON, challenge, "webauthn.create")) {
      throw new Error("Invalid client data");
    }
    const authData = authDataFromAttestationObject(attestationObject);
    if (!(await verifyRpIdHash(authData))) {
      throw new Error("RP ID hash mismatch");
    }
    if (!isUserPresent(authData)) {
      throw new Error("User presence flag not set");
    }

    const publicKey = arrayBufferToBase64Url(await credentialPublicKeyFromAuthData(authData));

    // Without PRF there is no key to store the wallet under: fail before
    // any record exists, so the passkey can be dropped
    const prfOutput =
      (isUserVerified(authData)
        ? copyPrfResult(credential.getClientExtensionResults?.().prf?.results?.first)
        : undefined) ?? (await evaluatePrf(PRF_INPUT, credential.id)).output;
    const publicKeyMac = await macPublicKey(prfOutput, credential.id, publicKey);

    // Past this point a record may be on disk, so the passkey must stay
    unstored = null;
    await storage.saveCredential({
      id: credential.id,
      publicKey,
      username,
      ethereumAddress,
      createdAt: new Date().toISOString(),
      lastUsed: new Date().toISOString(),
      signCount: 0, // Initialize signature counter
      publicKeyMac,
    });

    return { credentialId: credential.id, publicKey, signature: attestationObject, prfOutput };
  } catch (error) {
    if (unstored) signalUnknownCredential(unstored.rpId, unstored.credentialId);
    if (error instanceof PrfUnsupportedError) throw error;
    throw new RegistrationError(
      error instanceof Error ? error.message : "Registration failed",
      error
    );
  }
}
