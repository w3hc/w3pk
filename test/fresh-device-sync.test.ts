/**
 * syncWalletWithPasskey() with password backups on a device without the
 * passkey's metadata or wallet (PRF backups: prf-sync.test.ts)
 *
 * Mocks navigator.credentials.get with a real P-256 signed assertion, so a
 * login() after the sync runs the SDK's signature verification unchanged.
 *
 * NOTE: the mnemonic is the standard BIP39 test vector, not a real secret
 */

import { Wallet } from "ethers";
import {
  Web3Passkey,
  SyncBootstrapError,
  WalletError,
  Web3PasskeyError,
} from "../src/index";
import { CredentialStorage } from "../src/auth/storage";
import { BackupFileManager } from "../src/backup/backup-file";
import { arrayBufferToBase64Url } from "../src/utils/base64";

console.log("\n==================================================");
console.log("🔄 Fresh-Device Sync Test");
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
const PASSWORD = "correct horse battery staple";
const CREDENTIAL_ID = arrayBufferToBase64Url(
  crypto.getRandomValues(new Uint8Array(16)).buffer
);
const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ADDRESS = Wallet.fromPhrase(MNEMONIC).address;

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
      userAgent: "node",
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
              userHandle: new TextEncoder().encode(USERNAME).buffer,
            },
            getClientExtensionResults: () => ({}),
          };
        },
      },
    },
  });

  return arrayBufferToBase64Url(spki);
}

async function saveCredential(publicKey: string) {
  const now = new Date().toISOString();
  await new CredentialStorage(localStorage as unknown as Storage).saveCredential({
    id: CREDENTIAL_ID,
    publicKey,
    username: USERNAME,
    ethereumAddress: ADDRESS,
    createdAt: now,
    lastUsed: now,
  });
}

async function passwordBackupFromDeviceA(publicKey: string): Promise<string> {
  localStorage.clear();
  await saveCredential(publicKey);
  const sdk = new Web3Passkey();
  (sdk as any).currentUser = {
    username: USERNAME,
    ethereumAddress: ADDRESS,
    credentialId: CREDENTIAL_ID,
  };
  (sdk as any).getMnemonicFromSession = async () => MNEMONIC;
  const { blob } = await sdk.createBackupFile("password", PASSWORD);
  localStorage.clear();
  return blob.text();
}

function freshSdk() {
  const authEvents: boolean[] = [];
  const sdk = new Web3Passkey({
    onAuthStateChanged: (isAuthenticated) => authEvents.push(isAuthenticated),
  });
  return { sdk, authEvents };
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

  async function assertSyncedAndLogsIn(
    sdk: Web3Passkey,
    authEvents: boolean[],
    publicKey: string
  ) {
    assert(sdk.isAuthenticated, "user is logged in");
    assert(sdk.user?.ethereumAddress === ADDRESS, "user has the backup's address");
    assert(sdk.user?.username === USERNAME, "username comes from the passkey");
    assert(sdk.user?.credentialId === CREDENTIAL_ID, "user has the passkey's id");
    assert(authEvents.includes(true), "onAuthStateChanged(true) fires");

    const stored = await new CredentialStorage(
      localStorage as unknown as Storage
    ).getCredentialById(CREDENTIAL_ID);
    assert(stored?.publicKey === publicKey, "credential metadata has the public key");
    assert(stored?.ethereumAddress === ADDRESS, "credential metadata has the address");

    const next = freshSdk();
    const loginError = await capture(() => next.sdk.login());
    assert(loginError === undefined, "a later login() succeeds");
    assert(
      next.sdk.user?.ethereumAddress === ADDRESS,
      "login() opens the synced wallet"
    );
  }

  const publicKey = await setupAuthenticator();
  const manager = new BackupFileManager();

  console.log("Test 1: password backup carries the passkey credential");
  {
    const json = await passwordBackupFromDeviceA(publicKey);
    const backup = JSON.parse(json);
    assert(backup.credential?.id === CREDENTIAL_ID, "backup names the passkey");
    assert(backup.credential?.publicKey === publicKey, "backup has its public key");
  }
  console.log("");

  console.log("Test 2: syncWalletWithPasskey on a fresh device");
  {
    const json = await passwordBackupFromDeviceA(publicKey);
    const { sdk, authEvents } = freshSdk();
    const result = await sdk.syncWalletWithPasskey(json, PASSWORD);
    assert(result.ethereumAddress === ADDRESS, "returns the backup's address");
    assert(result.mnemonic === MNEMONIC, "returns the mnemonic");
    await assertSyncedAndLogsIn(sdk, authEvents, publicKey);
  }
  console.log("");

  console.log("Test 3: syncWalletWithPasskey with metadata but no wallet");
  {
    const json = await passwordBackupFromDeviceA(publicKey);
    await saveCredential(publicKey);
    const { sdk, authEvents } = freshSdk();
    await sdk.syncWalletWithPasskey(json, PASSWORD);
    await assertSyncedAndLogsIn(sdk, authEvents, publicKey);
  }
  console.log("");

  async function assertBootstrapError(
    label: string,
    fn: (sdk: Web3Passkey) => Promise<unknown>,
    reason: string
  ) {
    const { sdk, authEvents } = freshSdk();
    const error = await capture(() => fn(sdk));
    assert(error instanceof SyncBootstrapError, `${label}: throws SyncBootstrapError`);
    assert(error instanceof Web3PasskeyError, `${label}: extends Web3PasskeyError`);
    assert(
      (error as SyncBootstrapError).code === "SYNC_BOOTSTRAP_FAILED",
      `${label}: has code SYNC_BOOTSTRAP_FAILED`
    );
    assert((error as SyncBootstrapError).reason === reason, `${label}: reason ${reason}`);
    assert(!sdk.isAuthenticated, `${label}: user is not logged in`);
    assert(!authEvents.includes(true), `${label}: onAuthStateChanged(true) never fires`);
    assert(
      (await new CredentialStorage(localStorage as unknown as Storage).getAllCredentials())
        .length === 0,
      `${label}: no credential metadata is saved`
    );
  }

  console.log("Test 4: fresh device refuses what it can't bootstrap");
  {
    localStorage.clear();
    const { json: passkeyJson } = await manager.createPasskeyBackup(
      MNEMONIC,
      ADDRESS,
      CREDENTIAL_ID,
      publicKey
    );
    const { json: hybridJson } = await manager.createHybridBackup(
      MNEMONIC,
      ADDRESS,
      PASSWORD,
      CREDENTIAL_ID,
      publicKey
    );
    const { json: legacyJson } = await manager.createPasswordBackup(
      MNEMONIC,
      ADDRESS,
      PASSWORD
    );
    const { json: otherJson } = await manager.createPasswordBackup(
      MNEMONIC,
      ADDRESS,
      PASSWORD,
      { id: "another-passkey", publicKey }
    );

    const otherKey = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const { json: forgedJson } = await manager.createPasswordBackup(
      MNEMONIC,
      ADDRESS,
      PASSWORD,
      {
        id: CREDENTIAL_ID,
        publicKey: arrayBufferToBase64Url(
          await crypto.subtle.exportKey("spki", otherKey.publicKey)
        ),
      }
    );

    await assertBootstrapError(
      "sync, backup with another public key",
      (sdk) => sdk.syncWalletWithPasskey(forgedJson, PASSWORD),
      "PUBLIC_KEY_MISMATCH"
    );
    await assertBootstrapError(
      "sync, passkey backup",
      (sdk) => sdk.syncWalletWithPasskey(passkeyJson),
      "PASSKEY_BACKUP"
    );
    await assertBootstrapError(
      "sync, hybrid backup",
      (sdk) => sdk.syncWalletWithPasskey(hybridJson, PASSWORD),
      "PASSKEY_BACKUP"
    );
    await assertBootstrapError(
      "sync, backup without credential",
      (sdk) => sdk.syncWalletWithPasskey(legacyJson, PASSWORD),
      "NO_CREDENTIAL"
    );
    await assertBootstrapError(
      "sync, backup of another passkey",
      (sdk) => sdk.syncWalletWithPasskey(otherJson, PASSWORD),
      "CREDENTIAL_MISMATCH"
    );

    const { sdk } = freshSdk();
    const importError = await capture(() => sdk.importFromSync(passkeyJson));
    assert(
      importError instanceof WalletError,
      "importFromSync refuses a passkey backup with WalletError"
    );
  }
  console.log("");

  console.log("==================================================");
  console.log(`✅ Fresh-Device Sync Tests: ${passed} passed, ${failed} failed`);
  console.log("==================================================\n");

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
