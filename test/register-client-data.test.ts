/**
 * Registration checks the attestation per WebAuthn L3 §7.1: client data type,
 * challenge and origin, the RP ID hash and the user-presence flag, before
 * storing the credential.
 */

import { mockLocalStorage } from "./setup";
import { register } from "../src/auth/register";
import { CredentialStorage } from "../src/auth/storage";
import { arrayBufferToBase64Url } from "../src/utils/base64";
import { runTestSuite, assert } from "./test-utils";

const RP_ID = window.location.hostname;
const USERNAME = "alice";
const ADDRESS = "0x1234567890123456789012345678901234567890";

const UP = 0x01;
const UV = 0x04;
const AT = 0x40;

interface Overrides {
  type?: string;
  challenge?: string;
  origin?: string;
  rpId?: string;
  flags?: number;
  clientDataJSON?: ArrayBuffer;
  attestationObject?: ArrayBuffer;
}

let next: Overrides = {};
let createdId: string | undefined;
let signalled: { rpId: string; credentialId: string }[] = [];
let publicKeyRaw: Uint8Array;

async function attestationObject(rpId: string, flags: number): Promise<ArrayBuffer> {
  const x = publicKeyRaw.slice(1, 33);
  const y = publicKeyRaw.slice(33, 65);
  const cose = [0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, ...x, 0x22, 0x58, 0x20, ...y];
  const credId = new Uint8Array(16);
  const authData = [
    ...new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rpId))
    ),
    flags | AT,
    0, 0, 0, 0,
    ...new Uint8Array(16),
    0, credId.length,
    ...credId,
    ...cose,
  ];
  const text = (s: string) => [0x60 | s.length, ...new TextEncoder().encode(s)];
  return new Uint8Array([
    0xa3,
    ...text("fmt"), ...text("none"),
    ...text("attStmt"), 0xa0,
    ...text("authData"), 0x59, authData.length >> 8, authData.length & 0xff,
    ...authData,
  ]).buffer;
}

async function setup() {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  publicKeyRaw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));

  Object.defineProperty(globalThis, "PublicKeyCredential", {
    configurable: true,
    value: {
      signalUnknownCredential: async (options: { rpId: string; credentialId: string }) => {
        signalled.push(options);
      },
    },
  });

  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: {
      credentials: {
        create: async ({ publicKey }: { publicKey: PublicKeyCredentialCreationOptions }) => ({
          id: (createdId = arrayBufferToBase64Url(crypto.getRandomValues(new Uint8Array(16)).buffer)),
          rawId: new Uint8Array(16).buffer,
          type: "public-key",
          response: {
            attestationObject: next.attestationObject ?? await attestationObject(
              next.rpId ?? RP_ID,
              next.flags ?? UP | UV
            ),
            clientDataJSON:
              next.clientDataJSON ??
              new TextEncoder().encode(
                JSON.stringify({
                  type: next.type ?? "webauthn.create",
                  challenge:
                    next.challenge ??
                    arrayBufferToBase64Url(publicKey.challenge as ArrayBuffer),
                  origin: next.origin ?? window.location.origin,
                })
              ).buffer,
          },
          getClientExtensionResults: () => ({}),
        }),
      },
    },
  });
}

async function attemptRegister(overrides: Overrides) {
  mockLocalStorage.clear();
  next = overrides;
  createdId = undefined;
  signalled = [];
  let error: Error | undefined;
  try {
    await register({ username: USERNAME, ethereumAddress: ADDRESS });
  } catch (e) {
    error = e as Error;
  }
  const stored = await new CredentialStorage(mockLocalStorage).userExists(USERNAME);
  return { error, stored };
}

function rejected(overrides: Overrides, what: string, message: string) {
  return async () => {
    const { error, stored } = await attemptRegister(overrides);
    assert(error?.message === message, `registration should reject ${what} with "${message}", got "${error?.message}"`);
    assert(!stored, `${what} should not store the credential`);
    assert(
      signalled.length === 1 && signalled[0].credentialId === createdId && signalled[0].rpId === RP_ID,
      `${what} should signal the unstored passkey as unknown`
    );
  };
}

setup().then(() =>
  runTestSuite("Registration Client Data Tests", [
    {
      name: "valid attestation is stored",
      fn: async () => {
        const { error, stored } = await attemptRegister({});
        assert(error === undefined, `registration should succeed: ${error?.message}`);
        assert(stored, "the credential should be stored");
        assert(signalled.length === 0, "a stored credential should not be signalled as unknown");
      },
    },
    {
      name: "clientDataJSON type webauthn.get is rejected",
      fn: rejected({ type: "webauthn.get" }, "a webauthn.get type", "Invalid client data"),
    },
    {
      name: "another challenge is rejected",
      fn: rejected(
        { challenge: arrayBufferToBase64Url(crypto.getRandomValues(new Uint8Array(32)).buffer) },
        "another challenge",
        "Invalid client data"
      ),
    },
    {
      name: "another origin is rejected",
      fn: rejected({ origin: "https://evil.example" }, "another origin", "Invalid client data"),
    },
    {
      name: "origin with another port is rejected",
      fn: rejected({ origin: `${window.location.origin}:3000` }, "another port", "Invalid client data"),
    },
    {
      name: "malformed clientDataJSON is rejected",
      fn: rejected(
        { clientDataJSON: new TextEncoder().encode("not json").buffer },
        "malformed client data",
        "Invalid client data"
      ),
    },
    {
      name: "another RP ID hash is rejected",
      fn: rejected({ rpId: "evil.example" }, "another RP ID hash", "RP ID hash mismatch"),
    },
    {
      name: "storage failure does not signal the passkey as unknown",
      fn: async () => {
        const setItem = mockLocalStorage.setItem;
        mockLocalStorage.setItem = () => {
          throw new Error("QuotaExceededError");
        };
        let result;
        try {
          result = await attemptRegister({});
        } finally {
          mockLocalStorage.setItem = setItem;
        }
        assert(result.error !== undefined, "registration should fail when storage fails");
        assert(signalled.length === 0, "a passkey that may be on record should not be signalled as unknown");
      },
    },
    {
      name: "attestation object that is not a CBOR map is rejected",
      fn: async () => {
        const { error, stored } = await attemptRegister({
          attestationObject: new Uint8Array([0x68, ...new TextEncoder().encode("authData"), 0x41, 0x00]).buffer,
        });
        assert(error !== undefined, "a bare authData pattern should be rejected");
        assert(!stored, "a malformed attestation object should not store the credential");
      },
    },
    {
      name: "missing user-presence flag is rejected",
      fn: rejected({ flags: UV }, "an attestation without UP", "User presence flag not set"),
    },
  ])
);
