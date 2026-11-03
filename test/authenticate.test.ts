/**
 * Assertion verification: signature counter (cloned authenticator) and
 * RP ID hash checks, through login() with real P-256 signatures.
 */

import { mockLocalStorage } from "./setup";
import { login, verifyAssertionSignature } from "../src/auth/authenticate";
import { CredentialStorage } from "../src/auth/storage";
import type { AuthenticationCredential } from "../src/auth/types";
import { arrayBufferToBase64Url } from "../src/utils/base64";
import { runTestSuite, assert, assertEqual } from "./test-utils";

const RP_ID = window.location.hostname;
const CREDENTIAL_ID = arrayBufferToBase64Url(
  crypto.getRandomValues(new Uint8Array(16)).buffer
);

const storage = new CredentialStorage(mockLocalStorage);
let keyPair: CryptoKeyPair;
let publicKey: string;

const next = { counter: 0, rpId: RP_ID };

const CHALLENGE = crypto.getRandomValues(new Uint8Array(32)).buffer;
const CHALLENGE_B64 = arrayBufferToBase64Url(CHALLENGE);

function rawToDer(raw: Uint8Array): Uint8Array {
  const int = (bytes: Uint8Array) => {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    let v = bytes.slice(i);
    if (v[0] & 0x80) v = Uint8Array.from([0, ...v]);
    return Uint8Array.from([0x02, v.length, ...v]);
  };
  const r = int(raw.slice(0, 32));
  const s = int(raw.slice(32));
  return Uint8Array.from([0x30, r.length + s.length, ...r, ...s]);
}

interface ClientDataOverrides {
  type?: string;
  challenge?: string;
  origin?: string;
  flags?: number;
}

async function buildAssertion(
  counter: number,
  rpId: string,
  challenge: ArrayBuffer = crypto.getRandomValues(new Uint8Array(32)).buffer,
  overrides: ClientDataOverrides = {}
): Promise<AuthenticationCredential> {
  const authenticatorData = new Uint8Array(37);
  authenticatorData.set(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rpId))
    ),
    0
  );
  authenticatorData[32] = overrides.flags ?? 0x05;
  new DataView(authenticatorData.buffer).setUint32(33, counter);

  const clientDataJSON = new TextEncoder().encode(
    JSON.stringify({
      type: overrides.type ?? "webauthn.get",
      challenge: overrides.challenge ?? arrayBufferToBase64Url(challenge),
      origin: overrides.origin ?? window.location.origin,
    })
  );
  const clientDataHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", clientDataJSON)
  );
  const raw = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      keyPair.privateKey,
      new Uint8Array([...authenticatorData, ...clientDataHash])
    )
  );

  return {
    id: CREDENTIAL_ID,
    rawId: new Uint8Array(16).buffer,
    type: "public-key",
    response: {
      authenticatorData: authenticatorData.buffer,
      clientDataJSON: clientDataJSON.buffer,
      signature: rawToDer(raw).buffer,
    },
    getClientExtensionResults: () => ({}),
  } as AuthenticationCredential;
}

async function setStoredCounter(signCount: number) {
  const now = new Date().toISOString();
  await storage.saveCredential({
    id: CREDENTIAL_ID,
    publicKey,
    username: "alice",
    ethereumAddress: "0x1234567890123456789012345678901234567890",
    createdAt: now,
    lastUsed: now,
    signCount,
  });
}

async function storedCounter(): Promise<number | undefined> {
  return (await storage.getCredentialById(CREDENTIAL_ID))?.signCount;
}

async function attemptLogin(counter: number, rpId = RP_ID) {
  next.counter = counter;
  next.rpId = rpId;
  try {
    return { result: await login(), error: undefined };
  } catch (error) {
    return { result: undefined, error: error as Error };
  }
}

async function setup() {
  keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  publicKey = arrayBufferToBase64Url(
    await crypto.subtle.exportKey("spki", keyPair.publicKey)
  );
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: {
      credentials: {
        get: async (options: CredentialRequestOptions) =>
          buildAssertion(
            next.counter,
            next.rpId,
            options.publicKey!.challenge as ArrayBuffer
          ),
      },
    },
  });
}

setup().then(() =>
  runTestSuite("Assertion Verification Tests", [
    {
      name: "counter equal to the stored one is rejected",
      fn: async () => {
        await setStoredCounter(5);
        const { error } = await attemptLogin(5);
        assert(error !== undefined, "login should reject a replayed counter");
        assertEqual(await storedCounter(), 5, "stored counter unchanged");
      },
    },
    {
      name: "counter lower than the stored one is rejected",
      fn: async () => {
        await setStoredCounter(5);
        const { error } = await attemptLogin(4);
        assert(error !== undefined, "login should reject a lower counter");
        assertEqual(await storedCounter(), 5, "stored counter unchanged");
      },
    },
    {
      name: "counter 0 is rejected once a counter is stored",
      fn: async () => {
        await setStoredCounter(5);
        const { error } = await attemptLogin(0);
        assert(error !== undefined, "login should reject a reset counter");
        assertEqual(await storedCounter(), 5, "stored counter unchanged");
      },
    },
    {
      name: "counter 0 with stored 0 is accepted",
      fn: async () => {
        await setStoredCounter(0);
        const { result, error } = await attemptLogin(0);
        assert(error === undefined, `login failed: ${error?.message}`);
        assert(result?.verified === true, "login should be verified");
        assertEqual(await storedCounter(), 0, "stored counter stays 0");
      },
    },
    {
      name: "increasing counter is accepted and stored",
      fn: async () => {
        await setStoredCounter(5);
        const first = await attemptLogin(6);
        assert(first.error === undefined, `login failed: ${first.error?.message}`);
        assertEqual(await storedCounter(), 6, "stored counter updated to 6");

        const replay = await attemptLogin(6);
        assert(replay.error !== undefined, "replaying the new counter should be rejected");
      },
    },
    {
      name: "wrong RP ID hash is rejected by login()",
      fn: async () => {
        await setStoredCounter(0);
        const { error } = await attemptLogin(1, "evil.example");
        assert(error !== undefined, "login should reject another RP ID");
        assertEqual(await storedCounter(), 0, "stored counter unchanged");
      },
    },
    {
      name: "wrong RP ID hash is rejected by verifyAssertionSignature()",
      fn: async () => {
        const valid = await buildAssertion(1, RP_ID, CHALLENGE);
        assert(
          await verifyAssertionSignature(valid, publicKey, CHALLENGE_B64),
          "a correctly signed assertion for this RP ID should verify"
        );
        const phished = await buildAssertion(1, "evil.example", CHALLENGE);
        assert(
          !(await verifyAssertionSignature(phished, publicKey, CHALLENGE_B64)),
          "an assertion for another RP ID should not verify"
        );
      },
    },
    {
      name: "clientDataJSON type other than webauthn.get is rejected",
      fn: async () => {
        const assertion = await buildAssertion(1, RP_ID, CHALLENGE, { type: "webauthn.create" });
        assert(
          !(await verifyAssertionSignature(assertion, publicKey, CHALLENGE_B64)),
          "a webauthn.create client data should not verify"
        );
      },
    },
    {
      name: "challenge other than the one sent is rejected",
      fn: async () => {
        const assertion = await buildAssertion(1, RP_ID);
        assert(
          !(await verifyAssertionSignature(assertion, publicKey, CHALLENGE_B64)),
          "an assertion for another challenge should not verify"
        );
      },
    },
    {
      name: "origin other than this page's is rejected",
      fn: async () => {
        const assertion = await buildAssertion(1, RP_ID, CHALLENGE, {
          origin: "https://evil.example",
        });
        assert(
          !(await verifyAssertionSignature(assertion, publicKey, CHALLENGE_B64)),
          "an assertion from another origin should not verify"
        );
      },
    },
    {
      name: "missing user-presence flag is rejected",
      fn: async () => {
        const assertion = await buildAssertion(1, RP_ID, CHALLENGE, { flags: 0x04 });
        assert(
          !(await verifyAssertionSignature(assertion, publicKey, CHALLENGE_B64)),
          "an assertion without UP should not verify"
        );
      },
    },
    {
      name: "malformed clientDataJSON is rejected",
      fn: async () => {
        const assertion = await buildAssertion(1, RP_ID, CHALLENGE);
        assertion.response.clientDataJSON = new TextEncoder().encode("not json").buffer;
        assert(
          !(await verifyAssertionSignature(assertion, publicKey, CHALLENGE_B64)),
          "malformed client data should not verify"
        );
      },
    },
  ])
);
