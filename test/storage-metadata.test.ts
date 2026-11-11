/**
 * Credential metadata in localStorage is authenticated (audit L-3, I-1, I-3):
 * the PRIMARY public key by a MAC under the PRF output, checked at login;
 * wallet and session records by their AES-GCM additional data
 *
 * NOTE: the mnemonic is the standard BIP39 test vector, not a real secret
 */

import { Wallet } from "ethers";
import { Web3Passkey, AuthenticationError, WalletMissingError, CryptoError } from "../src/index";
import { CredentialStorage } from "../src/auth/storage";
import { LocalStorageWalletStorage, openWalletRecord, sealWalletRecord } from "../src/wallet/storage";
import { SessionManager } from "../src/core/session";
import {
  PersistentSessionStorage,
  openSessionRecord,
  sealSessionRecord,
  type PersistentSessionData,
} from "../src/core/persistent-session";
import {
  derivePrfSessionKey,
  deriveWalletKey,
  macPublicKey,
  verifyPublicKeyMac,
} from "../src/wallet/crypto";
import { getSmartAccountAddress } from "../src/wallet/smart-account";
import { arrayBufferToBase64Url } from "../src/utils/base64";

console.log("\n==================================================");
console.log("🔐 Storage Metadata Authentication Test");
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
const ADDRESS = Wallet.fromPhrase(MNEMONIC).address;
const CREDENTIAL_ID = arrayBufferToBase64Url(
  crypto.getRandomValues(new Uint8Array(16)).buffer
);
const UP_UV = 0x05;
const AT = 0x40;

const localStorage = new MemoryStorage();
(globalThis as any).localStorage = localStorage;
(globalThis as any).window = {
  location: { hostname: RP_ID, origin: `http://${RP_ID}` },
  localStorage,
};

const prfOutput = crypto.getRandomValues(new Uint8Array(32));
const authenticator = { getCalls: 0 };

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
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(RP_ID)));
}

/** Minimal "none" attestation object with an ES256 COSE key */
async function attestationObject(publicKeyRaw: Uint8Array): Promise<ArrayBuffer> {
  const x = publicKeyRaw.slice(1, 33);
  const y = publicKeyRaw.slice(33, 65);
  const cose = [0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, ...x, 0x22, 0x58, 0x20, ...y];
  const credId = new Uint8Array(16);
  const authData = [
    ...(await rpIdHash()),
    UP_UV | AT,
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

const spki = async (key: CryptoKey) => arrayBufferToBase64Url(await crypto.subtle.exportKey("spki", key));

async function newKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
}

async function setupAuthenticator(keyPair: CryptoKeyPair): Promise<void> {
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  let signCount = 0;
  const prfResults = (extensions: any) =>
    extensions?.prf?.eval?.first ? { prf: { results: { first: prfOutput.slice().buffer } } } : {};

  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: {
      userAgent: "node",
      credentials: {
        create: async ({ publicKey }: { publicKey: PublicKeyCredentialCreationOptions }) => ({
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
          getClientExtensionResults: () => prfResults(publicKey.extensions),
        }),
        get: async ({ publicKey }: { publicKey: PublicKeyCredentialRequestOptions }) => {
          authenticator.getCalls++;
          signCount++;
          const authenticatorData = new Uint8Array(37);
          authenticatorData.set(await rpIdHash(), 0);
          authenticatorData[32] = UP_UV;
          new DataView(authenticatorData.buffer).setUint32(33, signCount);
          const clientDataJSON = new TextEncoder().encode(
            JSON.stringify({
              type: "webauthn.get",
              challenge: arrayBufferToBase64Url(publicKey.challenge as ArrayBuffer),
              origin: `http://${RP_ID}`,
            })
          );
          const clientDataHash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataJSON));
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
            getClientExtensionResults: () => prfResults(publicKey.extensions),
          };
        },
      },
    },
  });
}

const credentials = () => new CredentialStorage(localStorage as unknown as Storage);
const wallets = () => new LocalStorageWalletStorage(localStorage as unknown as Storage);
const sessions = () => new PersistentSessionStorage(localStorage as unknown as Storage);

async function registered(config: ConstructorParameters<typeof Web3Passkey>[0] = {}): Promise<Web3Passkey> {
  localStorage.clear();
  const sdk = new Web3Passkey(config);
  (sdk as any).currentWallet = { address: ADDRESS, mnemonic: MNEMONIC };
  await sdk.register({ username: USERNAME });
  return sdk;
}

async function editCredential(changes: Record<string, unknown>): Promise<void> {
  const key = `w3pk_credential_${CREDENTIAL_ID}`;
  localStorage.setItem(key, JSON.stringify({ ...JSON.parse(localStorage.getItem(key)!), ...changes }));
}

async function capture(fn: () => Promise<unknown>): Promise<unknown> {
  try {
    await fn();
  } catch (e) {
    return e;
  }
  return undefined;
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

  const keyPair = await newKeyPair();
  const publicKey = await spki(keyPair.publicKey);
  const otherPublicKey = await spki((await newKeyPair()).publicKey);
  const primaryAddress = await getSmartAccountAddress(publicKey);
  await setupAuthenticator(keyPair);

  console.log("Test 1: register() stores the public key with its MAC under the PRF output");
  {
    await registered();
    const stored = (await credentials().getCredentialById(CREDENTIAL_ID))!;
    assert(stored.publicKey === publicKey, "the public key is stored");
    assert(
      await verifyPublicKeyMac(prfOutput, CREDENTIAL_ID, publicKey, stored.publicKeyMac),
      "its MAC checks under the PRF output"
    );
    assert(
      !(await verifyPublicKeyMac(crypto.getRandomValues(new Uint8Array(32)), CREDENTIAL_ID, publicKey, stored.publicKeyMac)),
      "not under another PRF output"
    );
    assert(
      !(await verifyPublicKeyMac(prfOutput, CREDENTIAL_ID, otherPublicKey, stored.publicKeyMac)),
      "nor for another public key"
    );
    assert(
      !(await verifyPublicKeyMac(prfOutput, "other-credential", publicKey, stored.publicKeyMac)),
      "nor for another credential"
    );
    assert(
      localStorage.getItem(`w3pk_credential_${CREDENTIAL_ID}`) !== null,
      "the record is stored under the raw credential ID"
    );
    assert(
      JSON.parse(localStorage.getItem("w3pk_credential_index")!).join() === CREDENTIAL_ID,
      "the index lists the same raw ID"
    );
  }
  console.log("");

  console.log("Test 2: login() checks the MAC and derives PRIMARY from the key it checked");
  {
    await registered();
    const sdk = new Web3Passkey();
    await sdk.login();
    assert(sdk.isAuthenticated, "login() succeeds");
    assert((await sdk.getAddress("PRIMARY")) === primaryAddress, "PRIMARY is the passkey's account");

    await editCredential({ publicKey: otherPublicKey });
    assert(
      (await sdk.getAddress("PRIMARY")) === primaryAddress,
      "a public key changed after login doesn't change the PRIMARY address"
    );
    assert(
      (await sdk.deriveWallet("PRIMARY")).publicKey === publicKey,
      "deriveWallet('PRIMARY') returns the key checked at login"
    );
  }
  console.log("");

  for (const [name, changes] of [
    ["no MAC", { publicKeyMac: undefined }],
    ["a MAC under another PRF output", {
      publicKeyMac: await macPublicKey(crypto.getRandomValues(new Uint8Array(32)), CREDENTIAL_ID, publicKey),
    }],
    ["the MAC of another public key", {
      publicKeyMac: await macPublicKey(prfOutput, CREDENTIAL_ID, otherPublicKey),
    }],
  ] as const) {
    console.log(`Test 3: login() refuses a public key with ${name}`);
    await registered();
    await editCredential(changes);
    const sdk = new Web3Passkey();
    const error = await capture(() => sdk.login());
    assert(error instanceof AuthenticationError, "login() throws AuthenticationError");
    assert(!sdk.isAuthenticated, "the user stays logged out");
    assert(
      (await capture(() => sdk.getAddress("PRIMARY"))) instanceof Error,
      "no PRIMARY address is shown"
    );
    console.log("");
  }

  console.log("Test 4: login() refuses a public key changed in storage");
  {
    await registered();
    await editCredential({ publicKey: otherPublicKey });
    const sdk = new Web3Passkey();
    const error = await capture(() => sdk.login());
    assert(error instanceof AuthenticationError, "login() throws AuthenticationError");
    assert(!sdk.isAuthenticated, "the user stays logged out");
  }
  console.log("");

  console.log("Test 5: silent restore refuses a public key changed in storage");
  {
    const config = { persistentSession: { enabled: true, requireReauth: false } };
    await registered(config);

    authenticator.getCalls = 0;
    const restored = new Web3Passkey(config);
    await restored.login();
    assert(authenticator.getCalls === 0, "an untouched session restores without a prompt");
    assert((await restored.getAddress("PRIMARY")) === primaryAddress, "with the passkey's PRIMARY address");

    await editCredential({ publicKey: otherPublicKey });
    const manager = new SessionManager(1, config.persistentSession);
    assert((await manager.attemptSilentRestore()) === null, "the session no longer restores");
    const sdk = new Web3Passkey(config);
    const error = await capture(() => sdk.login());
    assert(authenticator.getCalls > 0, "login() falls back to a prompt");
    assert(error instanceof AuthenticationError, "which fails against the changed key");
    assert(!sdk.isAuthenticated, "the user stays logged out");
  }
  console.log("");

  console.log("Test 6: a wallet record with edited metadata doesn't decrypt");
  {
    await registered();
    const record = (await wallets().retrieve(CREDENTIAL_ID))!;
    const key = await deriveWalletKey(prfOutput);
    assert((await openWalletRecord(record, key)) === MNEMONIC, "the untouched record decrypts");
    for (const [field, value] of [
      ["credentialId", "other-credential"],
      ["ethereumAddress", "0x0000000000000000000000000000000000000001"],
      ["createdAt", new Date(0).toISOString()],
    ]) {
      const error = await capture(() => openWalletRecord({ ...record, [field]: value }, key));
      assert(error instanceof CryptoError, `edited ${field}: throws CryptoError`);
    }

    await wallets().store({ ...record, createdAt: new Date(0).toISOString() });
    const sdk = new Web3Passkey();
    const error = await capture(() => sdk.login());
    assert(error instanceof WalletMissingError, "login() with an edited record throws WalletMissingError");
    assert(!sdk.isAuthenticated, "the user stays logged out");

    const sealed = await sealWalletRecord(MNEMONIC, key, {
      credentialId: CREDENTIAL_ID,
      ethereumAddress: ADDRESS,
      createdAt: record.createdAt,
    });
    await wallets().store(sealed);
    const reopened = new Web3Passkey();
    await reopened.login();
    assert(reopened.isAuthenticated, "a record sealed with the same metadata opens again");
  }
  console.log("");

  console.log("Test 7: a session record with edited metadata doesn't decrypt");
  {
    const key = await derivePrfSessionKey(prfOutput);
    const record: PersistentSessionData = await sealSessionRecord(
      MNEMONIC,
      key,
      {
        credentialId: CREDENTIAL_ID,
        ethereumAddress: ADDRESS,
        expiresAt: Date.now() + 60_000,
        securityMode: "STANDARD",
        createdAt: Date.now(),
      },
      publicKey
    );
    assert((await openSessionRecord(record, key, publicKey)) === MNEMONIC, "the untouched record decrypts");
    for (const [field, value] of [
      ["credentialId", "other-credential"],
      ["ethereumAddress", "0x0000000000000000000000000000000000000001"],
      ["expiresAt", record.expiresAt + 365 * 24 * 3600_000],
      ["securityMode", "YOLO"],
      ["createdAt", 0],
    ] as const) {
      const error = await capture(() => openSessionRecord({ ...record, [field]: value }, key, publicKey));
      assert(error instanceof CryptoError, `edited ${field}: throws CryptoError`);
    }
    assert(
      (await capture(() => openSessionRecord(record, key, otherPublicKey))) instanceof CryptoError,
      "another public key: throws CryptoError"
    );

    localStorage.clear();
    const manager = new SessionManager(1, { enabled: true });
    const account = { ethereumAddress: ADDRESS, publicKey };
    await sessions().store({ ...record, expiresAt: record.expiresAt + 365 * 24 * 3600_000 });
    assert(
      (await manager.restoreFromPersistentStorage(account, CREDENTIAL_ID, key)) === null,
      "an extended expiry doesn't restore"
    );
    assert((await sessions().retrieve(CREDENTIAL_ID)) === null, "and the record is deleted");
    await sessions().store(record);
    assert(
      (await manager.restoreFromPersistentStorage(account, CREDENTIAL_ID, key)) === MNEMONIC,
      "the untouched record restores"
    );
  }
  console.log("");

  console.log("==================================================");
  console.log(`✅ Storage Metadata Tests: ${passed} passed, ${failed} failed`);
  console.log("==================================================\n");
  if (failed > 0) process.exit(1);
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
