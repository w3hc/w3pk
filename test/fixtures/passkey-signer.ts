/**
 * Software passkey for PRIMARY mode signing: answers navigator.credentials.get
 * with a WebAuthn assertion (UP | UV, origin http://localhost) signed by the
 * P-256 key of scalar 0xa11ce, deterministically (RFC 6979)
 *
 * The key is the one test/smart-account-address.test.ts and the forge tests use.
 * NOTE: the mnemonic is the standard Hardhat test vector, not a real secret
 */

import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { mockLocalStorage } from "../setup";
import { createWeb3Passkey } from "../../src/index";
import { CredentialStorage } from "../../src/auth/storage";
import type { Web3PasskeyConfig } from "../../src/core/config";

export const PRIVATE_KEY = 0xa11cen;
export const QX = "0x7268876e19db7d7a651d55d5f3cd08b0f14f0f2d99ac383d56e705cc58b2de09";
export const QY = "0x272f3460d10844d9d8a77c0f6f5754c8e1c7fa3a58c6671f9199d8710af43878";
export const PUBLIC_KEY_SPKI = Buffer.from(
  "3059301306072a8648ce3d020106082a8648ce3d03010703420004" + QX.slice(2) + QY.slice(2),
  "hex"
).toString("base64url");
export const MAIN_ACCOUNT = "0xC92aa436a4B825382f79c4d7a972b76409A45fC2";
export const GAMING_ACCOUNT = "0x9bd3912f41dbA1b66425bD5B6046A31685b17143";
export const CREDENTIAL_ID = "cHJpbWFyeS1zaWduZXI";
export const ORIGIN = "http://localhost";

const MNEMONIC = "test test test test test test test test test test test junk";
const UP_UV = 0x05;

export const passkeyCalls: PublicKeyCredentialRequestOptions[] = [];

export function installPasskey(): void {
  const privateKey = new Uint8Array(Buffer.from(PRIVATE_KEY.toString(16).padStart(64, "0"), "hex"));
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: {
      userAgent: "node",
      credentials: {
        get: async ({ publicKey }: { publicKey: PublicKeyCredentialRequestOptions }) => {
          passkeyCalls.push(publicKey);
          const challenge = Buffer.from(publicKey.challenge as Uint8Array).toString("base64url");
          const clientDataJSON = new TextEncoder().encode(
            `{"type":"webauthn.get","challenge":"${challenge}","origin":"${ORIGIN}","crossOrigin":false}`
          );
          const authenticatorData = new Uint8Array([
            ...sha256(new TextEncoder().encode("localhost")),
            UP_UV,
            0, 0, 0, 1,
          ]);
          const signature = p256.sign(
            new Uint8Array([...authenticatorData, ...sha256(clientDataJSON)]),
            privateKey,
            { format: "der" }
          );
          return {
            id: CREDENTIAL_ID,
            type: "public-key",
            response: {
              authenticatorData: authenticatorData.buffer,
              clientDataJSON: clientDataJSON.buffer,
              signature: signature.slice().buffer,
            },
          };
        },
      },
    },
  });
}

/** An SDK logged in with the software passkey, with no RPC endpoint unless configured */
export async function primarySdk(config: Web3PasskeyConfig = {}) {
  await new CredentialStorage(mockLocalStorage).saveCredential({
    id: CREDENTIAL_ID,
    publicKey: PUBLIC_KEY_SPKI,
    username: "primary-signer",
    ethereumAddress: MAIN_ACCOUNT,
    createdAt: new Date().toISOString(),
    lastUsed: new Date().toISOString(),
  });
  const sdk = createWeb3Passkey({ storage: mockLocalStorage, debug: false, ...config });
  (sdk as any).currentUser = {
    username: "primary-signer",
    ethereumAddress: MAIN_ACCOUNT,
    credentialId: CREDENTIAL_ID,
  };
  (sdk as any).getMnemonicFromSession = async () => MNEMONIC;
  return sdk;
}
