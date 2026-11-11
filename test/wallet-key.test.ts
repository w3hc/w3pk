/**
 * The wallet stored on the device is encrypted under a key derived from the
 * passkey's PRF output: register() and login() with and without PRF, and
 * records stored under the old key built from stored data. Once a session
 * starts, only the session holds the mnemonic in memory, for its lifetime.
 *
 * NOTE: the mnemonic is the standard BIP39 test vector, not a real secret
 */

import { Web3Passkey, WalletMissingError, PrfUnsupportedError } from "../src/index";
import { CredentialStorage } from "../src/auth/storage";
import { LocalStorageWalletStorage, openWalletRecord, sealWalletRecord } from "../src/wallet/storage";
import type { SessionManager } from "../src/core/session";
import { deriveWalletKey, encryptData, PRF_INPUT } from "../src/wallet/crypto";
import { arrayBufferToBase64Url } from "../src/utils/base64";

console.log("\n==================================================");
console.log("🔑 Wallet Key Test");
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
const USERNAME = "alice";
const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const CREDENTIAL_ID = arrayBufferToBase64Url(
  crypto.getRandomValues(new Uint8Array(16)).buffer
);

const UP = 0x01;
const UV = 0x04;
const AT = 0x40;

const localStorage = new MemoryStorage();
(globalThis as any).localStorage = localStorage;
(globalThis as any).window = {
  location: { hostname: RP_ID, origin: `http://${RP_ID}` },
  localStorage,
};

const authenticator = {
  prfOnCreate: true,
  prfOnGet: true,
  prfOutput: crypto.getRandomValues(new Uint8Array(32)).buffer,
  createCalls: 0,
  getCalls: [] as PublicKeyCredentialRequestOptions[],
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

async function rpIdHash(): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(RP_ID))
  );
}

/** Minimal "none" attestation object with an ES256 COSE key */
async function attestationObject(publicKeyRaw: Uint8Array): Promise<ArrayBuffer> {
  const x = publicKeyRaw.slice(1, 33);
  const y = publicKeyRaw.slice(33, 65);
  const cose = [0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, ...x, 0x22, 0x58, 0x20, ...y];
  const credId = new Uint8Array(16);
  const authData = [
    ...(await rpIdHash()),
    UP | UV | AT,
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

async function setupAuthenticator(): Promise<void> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  let signCount = 0;

  const prfResults = (enabled: boolean, extensions: any) =>
    enabled && extensions?.prf?.eval?.first
      ? { prf: { results: { first: authenticator.prfOutput } } }
      : {};

  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: {
      userAgent: "node",
      credentials: {
        create: async ({ publicKey }: { publicKey: PublicKeyCredentialCreationOptions }) => {
          authenticator.createCalls++;
          return {
            id: CREDENTIAL_ID,
            rawId: new Uint8Array(16).buffer,
            type: "public-key",
            response: {
              attestationObject: await attestationObject(raw),
              clientDataJSON: new TextEncoder().encode(
                JSON.stringify({
                  type: "webauthn.create",
                  challenge: arrayBufferToBase64Url(publicKey.challenge as ArrayBuffer),
                  origin: `http://${RP_ID}`,
                })
              ).buffer,
            },
            getClientExtensionResults: () =>
              prfResults(authenticator.prfOnCreate, publicKey.extensions),
          };
        },
        get: async ({ publicKey }: { publicKey: PublicKeyCredentialRequestOptions }) => {
          authenticator.getCalls.push(publicKey);

          signCount++;
          const authenticatorData = new Uint8Array(37);
          authenticatorData.set(await rpIdHash(), 0);
          authenticatorData[32] = UP | UV;
          new DataView(authenticatorData.buffer).setUint32(33, signCount);

          const clientDataJSON = new TextEncoder().encode(
            JSON.stringify({
              type: "webauthn.get",
              challenge: arrayBufferToBase64Url(publicKey.challenge as ArrayBuffer),
              origin: `http://${RP_ID}`,
            })
          );
          const clientDataHash = new Uint8Array(
            await crypto.subtle.digest("SHA-256", clientDataJSON)
          );
          const signature = new Uint8Array(
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
              signature: rawToDer(signature).buffer,
              userHandle: new TextEncoder().encode(USERNAME).buffer,
            },
            getClientExtensionResults: () =>
              prfResults(authenticator.prfOnGet, publicKey.extensions),
          };
        },
      },
    },
  });
}

function reset(prfOnCreate: boolean, prfOnGet: boolean) {
  localStorage.clear();
  authenticator.prfOnCreate = prfOnCreate;
  authenticator.prfOnGet = prfOnGet;
  authenticator.createCalls = 0;
  authenticator.getCalls = [];
}

const wallets = () => new LocalStorageWalletStorage(localStorage as unknown as Storage);

async function registerWithMnemonic(sdk: Web3Passkey): Promise<string> {
  (sdk as any).currentWallet = {
    address: (await import("ethers")).Wallet.fromPhrase(MNEMONIC).address,
    mnemonic: MNEMONIC,
  };
  const { address } = await sdk.register({ username: USERNAME });
  return address;
}

async function decryptsWithWalletKey(address: string): Promise<boolean> {
  const stored = await wallets().retrieve(CREDENTIAL_ID);
  if (stored?.ethereumAddress !== address) return false;
  const key = await deriveWalletKey(authenticator.prfOutput);
  return openWalletRecord(stored, key).then(
    (m) => m === MNEMONIC,
    () => false
  );
}

/** Replace the stored record with one under a key that isn't the wallet key */
async function storeUnderOldKey(address: string): Promise<void> {
  const stored = (await wallets().retrieve(CREDENTIAL_ID))!;
  if (stored.ethereumAddress !== address) throw new Error("no record for this address");
  const oldKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  await wallets().store({
    ...stored,
    encryptedMnemonic: await encryptData(MNEMONIC, oldKey),
  });
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

  await setupAuthenticator();

  console.log("Test 1: register() with PRF at creation");
  {
    reset(true, true);
    const address = await registerWithMnemonic(new Web3Passkey());
    assert(authenticator.getCalls.length === 0, "no assertion after creation");
    assert(await decryptsWithWalletKey(address), "the stored wallet decrypts with the PRF wallet key");

    const next = new Web3Passkey();
    await next.login();
    assert(next.isAuthenticated, "a later login() opens the wallet");
  }
  console.log("");

  console.log("Test 2: register() without PRF at creation");
  {
    reset(false, true);
    const address = await registerWithMnemonic(new Web3Passkey());
    assert(authenticator.getCalls.length === 1, "one assertion evaluates the PRF");
    assert(
      authenticator.getCalls[0].extensions !== undefined &&
        (authenticator.getCalls[0].extensions as any).prf.eval.first === PRF_INPUT,
      "the assertion evaluates PRF_INPUT"
    );
    assert(await decryptsWithWalletKey(address), "the stored wallet decrypts with the PRF wallet key");
  }
  console.log("");

  console.log("Test 3: register() without PRF throws PrfUnsupportedError");
  {
    reset(false, false);
    const sdk = new Web3Passkey();
    const error = await registerWithMnemonic(sdk).then(() => undefined, (e) => e);
    assert(error instanceof PrfUnsupportedError, "register() throws PrfUnsupportedError");
    assert(!sdk.isAuthenticated, "the user stays logged out");
    assert((await wallets().retrieve(CREDENTIAL_ID)) === null, "no wallet is stored on the device");
    assert(
      !(await new CredentialStorage(localStorage as unknown as Storage).userExists(USERNAME)),
      "no credential is stored on the device"
    );
  }
  console.log("");

  console.log("Test 4: a record under the old key needs a backup");
  {
    reset(true, true);
    const address = await registerWithMnemonic(new Web3Passkey());
    await storeUnderOldKey(address);

    const next = new Web3Passkey();
    const pending = { address: "0x0", mnemonic: "pending" };
    (next as any).currentWallet = pending;
    const error = await next.login().then(() => undefined, (e) => e);
    assert(error instanceof WalletMissingError, "login() throws WalletMissingError");
    assert(!next.isAuthenticated, "the user stays logged out");
    assert((next as any).currentWallet === pending, "a wallet waiting for register() is kept");
  }
  console.log("");

  const session = (sdk: Web3Passkey) => (sdk as any).sessionManager as SessionManager;

  console.log("Test 5: register() leaves the mnemonic to the session");
  {
    reset(true, true);
    const sdk = new Web3Passkey();
    await registerWithMnemonic(sdk);
    assert((sdk as any).currentWallet === null, "no wallet is kept in memory");
    assert(session(sdk).getMnemonic() === MNEMONIC, "the session holds the mnemonic");
    await sdk.deriveWallet();
    assert(authenticator.getCalls.length === 0, "no passkey prompt within the session");
  }
  console.log("");

  console.log("Test 6: login() drops a wallet waiting for register()");
  {
    reset(true, true);
    await registerWithMnemonic(new Web3Passkey());
    const sdk = new Web3Passkey();
    (sdk as any).currentWallet = { address: "0x0", mnemonic: "pending" };
    await sdk.login();
    assert((sdk as any).currentWallet === null, "no wallet is kept in memory");
    assert(session(sdk).getMnemonic() === MNEMONIC, "the session holds the mnemonic");
  }
  console.log("");

  console.log("Test 7: nothing holds the mnemonic once the session expires");
  {
    reset(true, true);
    const sdk = new Web3Passkey();
    await registerWithMnemonic(sdk);
    assert(sdk.hasActiveSession(), "the session is live");
    (session(sdk) as any).session.expiresAt = new Date(Date.now() - 1).toISOString();
    assert(!sdk.hasActiveSession(), "the session has expired");
    assert((sdk as any).currentWallet === null, "no wallet is kept in memory");
    assert(session(sdk).getMnemonic() === null, "the session holds no mnemonic");
    await sdk.deriveWallet();
    assert(authenticator.getCalls.length === 1, "the next operation prompts");
  }
  console.log("");

  console.log("Test 8: sessionDuration: 0 keeps nothing in memory");
  {
    reset(true, true);
    const sdk = new Web3Passkey({ sessionDuration: 0 });
    await registerWithMnemonic(sdk);
    assert((sdk as any).currentWallet === null, "no wallet is kept in memory");
    assert(session(sdk).getMnemonic() === null, "the session holds no mnemonic");
    await sdk.deriveWallet();
    await sdk.deriveWallet();
    assert(authenticator.getCalls.length === 2, "every operation prompts");
    assert(session(sdk).getMnemonic() === null, "still nothing after an operation");
  }
  console.log("");

  console.log("Test 9: STRICT caches nothing");
  {
    reset(true, true);
    const sdk = new Web3Passkey({ persistentSession: { enabled: true } });
    await registerWithMnemonic(sdk);
    await session(sdk).clearSession();
    await sdk.deriveWallet("STRICT");
    assert(authenticator.getCalls.length === 1, "STRICT prompts");
    assert(session(sdk).getMnemonic() === null, "no session is started");
    const keys = Array.from({ length: localStorage.length }, (_, i) => localStorage.key(i));
    assert(!keys.some((k) => k?.startsWith("w3pk_session_")), "nothing is persisted");
  }
  console.log("");

  console.log("==================================================");
  console.log(`✅ Wallet Key Tests: ${passed} passed, ${failed} failed`);
  console.log("==================================================\n");

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
