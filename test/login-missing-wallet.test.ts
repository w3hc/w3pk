/**
 * login() with a passkey that has no wallet on this device
 *
 * Mocks navigator.credentials.get with a real P-256 signed assertion, so the
 * SDK's signature verification runs unchanged.
 */

import {
  Web3Passkey,
  SyncRequiredError,
  WalletMissingError,
  Web3PasskeyError,
} from "../src/index";
import { CredentialStorage } from "../src/auth/storage";
import { arrayBufferToBase64Url } from "../src/utils/base64";

console.log("\n==================================================");
console.log("🔐 login() Without a Wallet Test");
console.log("==================================================\n");

class MemoryStorage {
  private items = new Map<string, string>();
  get length() {
    return this.items.size;
  }
  key(i: number) {
    return [...this.items.keys()][i] ?? null;
  }
  getItem(k: string) {
    return this.items.get(k) ?? null;
  }
  setItem(k: string, v: string) {
    this.items.set(k, String(v));
  }
  removeItem(k: string) {
    this.items.delete(k);
  }
  clear() {
    this.items.clear();
  }
}

const RP_ID = "localhost";
const CREDENTIAL_ID = arrayBufferToBase64Url(
  crypto.getRandomValues(new Uint8Array(16)).buffer
);
const ADDRESS = "0x1234567890123456789012345678901234567890";

const localStorage = new MemoryStorage();
(globalThis as any).localStorage = localStorage;
(globalThis as any).window = {
  location: { hostname: RP_ID, origin: `http://${RP_ID}` },
  localStorage,
};

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

async function setupAuthenticator() {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  let signCount = 0;

  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: {
      credentials: {
        get: async () => {
          signCount++;
          const rpIdHash = new Uint8Array(
            await crypto.subtle.digest(
              "SHA-256",
              new TextEncoder().encode(RP_ID)
            )
          );
          const authenticatorData = new Uint8Array(37);
          authenticatorData.set(rpIdHash, 0);
          authenticatorData[32] = 0x05;
          new DataView(authenticatorData.buffer).setUint32(33, signCount);

          const clientDataJSON = new TextEncoder().encode(
            JSON.stringify({ type: "webauthn.get", origin: `http://${RP_ID}` })
          );
          const clientDataHash = new Uint8Array(
            await crypto.subtle.digest("SHA-256", clientDataJSON)
          );
          const signed = new Uint8Array([
            ...authenticatorData,
            ...clientDataHash,
          ]);
          const raw = new Uint8Array(
            await crypto.subtle.sign(
              { name: "ECDSA", hash: "SHA-256" },
              keyPair.privateKey,
              signed
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
          };
        },
      },
    },
  });

  return arrayBufferToBase64Url(spki);
}

async function runTests() {
  let passed = 0;
  let failed = 0;

  function assert(condition: boolean, message: string) {
    if (condition) {
      passed++;
      console.log(`  ✅ ${message}`);
    } else {
      failed++;
      console.log(`  ❌ ${message}`);
    }
  }

  const publicKey = await setupAuthenticator();

  async function attemptLogin() {
    const authEvents: boolean[] = [];
    const sdk = new Web3Passkey({
      onAuthStateChanged: (isAuthenticated) => authEvents.push(isAuthenticated),
    });
    let error: unknown;
    try {
      await sdk.login();
    } catch (e) {
      error = e;
    }
    return { sdk, authEvents, error };
  }

  console.log("Test 1: no credential metadata on this device");
  {
    const { sdk, authEvents, error } = await attemptLogin();
    assert(error instanceof SyncRequiredError, "throws SyncRequiredError");
    assert(error instanceof Web3PasskeyError, "extends Web3PasskeyError");
    assert(
      (error as SyncRequiredError).code === "SYNC_REQUIRED",
      "has code SYNC_REQUIRED"
    );
    assert(
      (error as SyncRequiredError).credentialId === CREDENTIAL_ID,
      "carries the credentialId"
    );
    assert(!sdk.isAuthenticated, "user is not logged in");
    assert(!authEvents.includes(true), "onAuthStateChanged(true) never fires");
  }
  console.log("");

  console.log("Test 2: credential metadata present, wallet record missing");
  {
    const now = new Date().toISOString();
    await new CredentialStorage(localStorage as unknown as Storage).saveCredential({
      id: CREDENTIAL_ID,
      publicKey,
      username: "alice",
      ethereumAddress: ADDRESS,
      createdAt: now,
      lastUsed: now,
    });

    const { sdk, authEvents, error } = await attemptLogin();
    assert(error instanceof WalletMissingError, "throws WalletMissingError");
    assert(error instanceof Web3PasskeyError, "extends Web3PasskeyError");
    assert(
      (error as WalletMissingError).code === "WALLET_MISSING",
      "has code WALLET_MISSING"
    );
    assert(
      (error as WalletMissingError).credentialId === CREDENTIAL_ID,
      "carries the credentialId"
    );
    assert(
      (error as WalletMissingError).ethereumAddress === ADDRESS,
      "carries the ethereumAddress"
    );
    assert(!sdk.isAuthenticated, "user is not logged in");
    assert(!authEvents.includes(true), "onAuthStateChanged(true) never fires");
  }
  console.log("");

  console.log("==================================================");
  console.log(`✅ login() Without a Wallet Tests: ${passed} passed, ${failed} failed`);
  console.log("==================================================\n");

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
