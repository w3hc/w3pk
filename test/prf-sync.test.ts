/**
 * PRF backups: exportForSync() on device A, syncWalletWithPasskey() and
 * importFromSync() on a fresh device B where the passkey synced
 *
 * Mocks navigator.credentials.get with a synced passkey: a P-256 key that
 * signs real assertions, and a PRF computed as the spec describes,
 * HMAC-SHA256(credential secret, SHA-256("WebAuthn PRF" || 0x00 || input)).
 *
 * NOTE: the mnemonic is the standard BIP39 test vector, not a real secret
 */

import { Wallet } from "ethers";
import {
  Web3Passkey,
  AuthenticationError,
  PrfUnsupportedError,
  SyncBootstrapError,
  WalletError,
} from "../src/index";
import { CredentialStorage } from "../src/auth/storage";
import { LocalStorageWalletStorage } from "../src/wallet/storage";
import { deriveEncryptionKeyFromWebAuthn, encryptData } from "../src/wallet/crypto";
import { BackupFileManager, prfSyncInput } from "../src/backup/backup-file";
import { DeviceSyncManager } from "../src/sync/backup-sync";
import type { BackupFile } from "../src/backup/types";
import { arrayBufferToBase64Url } from "../src/utils/base64";

console.log("\n==================================================");
console.log("🔐 PRF Sync Test");
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

const authenticator = {
  prf: true,
  available: true,
  secret: crypto.getRandomValues(new Uint8Array(32)),
  calls: [] as PublicKeyCredentialRequestOptions[],
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

async function prf(secret: Uint8Array, input: BufferSource): Promise<ArrayBuffer> {
  const label = new TextEncoder().encode("WebAuthn PRF");
  const bytes = new Uint8Array(
    ArrayBuffer.isView(input)
      ? input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength)
      : input
  );
  const salt = await crypto.subtle.digest(
    "SHA-256",
    new Uint8Array([...label, 0, ...bytes])
  );
  const key = await crypto.subtle.importKey(
    "raw",
    secret,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return crypto.subtle.sign("HMAC", key, salt);
}

async function setupAuthenticator(): Promise<string> {
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
        get: async ({ publicKey }: { publicKey: PublicKeyCredentialRequestOptions }) => {
          authenticator.calls.push(publicKey);
          if (!authenticator.available) {
            throw Object.assign(new Error("No passkey"), { name: "NotAllowedError" });
          }

          signCount++;
          const rpIdHash = new Uint8Array(
            await crypto.subtle.digest("SHA-256", new TextEncoder().encode(RP_ID))
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
          const raw = new Uint8Array(
            await crypto.subtle.sign(
              { name: "ECDSA", hash: "SHA-256" },
              keyPair.privateKey,
              new Uint8Array([...authenticatorData, ...clientDataHash])
            )
          );

          const input = (publicKey.extensions as any)?.prf?.eval?.first;
          const first =
            authenticator.prf && input ? await prf(authenticator.secret, input) : undefined;

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
            getClientExtensionResults: () =>
              first ? { prf: { results: { first } } } : {},
          };
        },
      },
    },
  });

  return arrayBufferToBase64Url(spki);
}

async function loggedInDeviceA(publicKey: string): Promise<Web3Passkey> {
  localStorage.clear();
  const now = new Date().toISOString();
  await new CredentialStorage(localStorage as unknown as Storage).saveCredential({
    id: CREDENTIAL_ID,
    publicKey,
    username: USERNAME,
    ethereumAddress: ADDRESS,
    createdAt: now,
    lastUsed: now,
  });
  const key = await deriveEncryptionKeyFromWebAuthn(CREDENTIAL_ID, publicKey);
  await new LocalStorageWalletStorage(localStorage as unknown as Storage).store({
    ethereumAddress: ADDRESS,
    encryptedMnemonic: await encryptData(MNEMONIC, key),
    credentialId: CREDENTIAL_ID,
    createdAt: now,
  });

  const sdk = new Web3Passkey();
  (sdk as any).currentUser = {
    username: USERNAME,
    ethereumAddress: ADDRESS,
    credentialId: CREDENTIAL_ID,
  };
  (sdk as any).getMnemonicFromSession = async () => MNEMONIC;
  return sdk;
}

async function exportFromDeviceA(
  publicKey: string,
  password?: string
): Promise<{ json: string; qrCode?: string; prompts: number }> {
  const sdk = await loggedInDeviceA(publicKey);
  authenticator.calls = [];
  const { blob, qrCode } = await sdk.exportForSync(password);
  const prompts = authenticator.calls.length;
  localStorage.clear();
  return { json: await blob.text(), qrCode, prompts };
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

function allowedIds(options: PublicKeyCredentialRequestOptions): string[] {
  return (options.allowCredentials ?? []).map((c) =>
    arrayBufferToBase64Url(c.id as ArrayBuffer)
  );
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

  async function assertNothingStored(label: string, sdk: Web3Passkey, authEvents: boolean[]) {
    assert(!sdk.isAuthenticated, `${label}: user is not logged in`);
    assert(!authEvents.includes(true), `${label}: onAuthStateChanged(true) never fires`);
    assert(
      (await new CredentialStorage(localStorage as unknown as Storage).getAllCredentials())
        .length === 0,
      `${label}: no credential metadata is saved`
    );
  }

  async function assertSyncedAndLogsIn(
    sdk: Web3Passkey,
    authEvents: boolean[],
    publicKey: string
  ) {
    assert(sdk.isAuthenticated, "user is logged in");
    assert(sdk.user?.ethereumAddress === ADDRESS, "user has the backup's address");
    assert(sdk.user?.username === USERNAME, "username comes from the backup");
    assert(sdk.user?.credentialId === CREDENTIAL_ID, "user has the passkey's id");
    assert(authEvents.includes(true), "onAuthStateChanged(true) fires");

    const stored = await new CredentialStorage(
      localStorage as unknown as Storage
    ).getCredentialById(CREDENTIAL_ID);
    assert(stored?.publicKey === publicKey, "credential metadata has the public key");

    const next = freshSdk();
    const loginError = await capture(() => next.sdk.login());
    assert(loginError === undefined, "a later login() verifies the signature and succeeds");
    assert(next.sdk.user?.ethereumAddress === ADDRESS, "login() opens the synced wallet");
  }

  const publicKey = await setupAuthenticator();
  const manager = new BackupFileManager();

  console.log("Test 1: exportForSync() emits a PRF backup with one prompt");
  const { json, qrCode, prompts } = await exportFromDeviceA(publicKey);
  const backup: BackupFile = JSON.parse(json);
  {
    assert(prompts === 1, "one passkey prompt");
    assert(backup.encryptionMethod === "prf", "encryptionMethod is 'prf'");
    assert(backup.credential?.id === CREDENTIAL_ID, "names the passkey");
    assert(backup.credential?.publicKey === publicKey, "carries its public key");
    assert(backup.username === USERNAME, "carries the username");
    assert(typeof backup.prfSalt === "string" && backup.prfSalt.length >= 43, "has a 32-byte prfSalt");
    assert(!backup.passwordEncryption, "no password encryption");
    assert(!json.includes("abandon"), "mnemonic isn't in clear");
    assert(typeof qrCode === "string" && qrCode.startsWith("data:image/png"), "QR code is generated");

    const again = await exportFromDeviceA(publicKey);
    assert(JSON.parse(again.json).prfSalt !== backup.prfSalt, "prfSalt is random per backup");
  }
  console.log("");

  console.log("Test 2: syncWalletWithPasskey() on a fresh device, no password");
  {
    localStorage.clear();
    authenticator.calls = [];
    const { sdk, authEvents } = freshSdk();
    const result = await sdk.syncWalletWithPasskey(json);
    assert(authenticator.calls.length === 1, "one passkey prompt");
    assert(
      allowedIds(authenticator.calls[0]).join() === CREDENTIAL_ID,
      "assertion is restricted to the backup's passkey"
    );
    assert(result.mnemonic === MNEMONIC, "returns the mnemonic");
    assert(result.ethereumAddress === ADDRESS, "returns the address");
    await assertSyncedAndLogsIn(sdk, authEvents, publicKey);
  }
  console.log("");

  console.log("Test 3: importFromSync() on a fresh device, logged out");
  {
    localStorage.clear();
    authenticator.calls = [];
    const { sdk, authEvents } = freshSdk();
    const result = await sdk.importFromSync(json);
    assert(authenticator.calls.length === 1, "one passkey prompt");
    assert(result.success && result.ethereumAddress === ADDRESS, "imports the wallet");
    await assertSyncedAndLogsIn(sdk, authEvents, publicKey);
  }
  console.log("");

  console.log("Test 4: a PRF backup can't be decrypted without the passkey");
  {
    const wrongOutput = crypto.getRandomValues(new Uint8Array(32));
    assert(
      (await capture(() => manager.restoreWithPrf(backup, wrongOutput))) instanceof Error,
      "a wrong PRF output fails"
    );

    const otherPasskeyOutput = await prf(
      crypto.getRandomValues(new Uint8Array(32)),
      await prfSyncInput(backup.prfSalt!)
    );
    assert(
      (await capture(() => manager.restoreWithPrf(backup, otherPasskeyOutput))) instanceof Error,
      "another passkey's PRF output fails"
    );

    const rightOutput = await prf(authenticator.secret, await prfSyncInput(backup.prfSalt!));
    const restored = await manager.restoreWithPrf(backup, rightOutput);
    assert(restored.mnemonic === MNEMONIC, "the passkey's PRF output decrypts it");

    localStorage.clear();
    authenticator.available = false;
    const { sdk, authEvents } = freshSdk();
    const error = await capture(() => sdk.syncWalletWithPasskey(json));
    authenticator.available = true;
    assert(error instanceof AuthenticationError, "sync without the passkey throws AuthenticationError");
    await assertNothingStored("no passkey", sdk, authEvents);
  }
  console.log("");

  console.log("Test 5: altered backups are rejected");
  {
    const flip = (s: string, i: number) =>
      s.slice(0, i) + (s[i] === "A" ? "B" : "A") + s.slice(i + 1);
    const otherAddress = Wallet.createRandom().address;
    const otherKey = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const otherPublicKey = arrayBufferToBase64Url(
      await crypto.subtle.exportKey("spki", otherKey.publicKey)
    );

    const cases: Array<[string, BackupFile]> = [
      ["altered addressChecksum", { ...backup, addressChecksum: flip(backup.addressChecksum, 0) }],
      ["altered ciphertext", { ...backup, encryptedMnemonic: flip(backup.encryptedMnemonic, 30) }],
      ["altered address", { ...backup, ethereumAddress: otherAddress }],
      ["altered prfSalt", { ...backup, prfSalt: flip(backup.prfSalt!, 5) }],
    ];
    for (const [label, altered] of cases) {
      localStorage.clear();
      const { sdk, authEvents } = freshSdk();
      const error = await capture(() => sdk.syncWalletWithPasskey(JSON.stringify(altered)));
      assert(error instanceof Error, `${label}: rejected`);
      await assertNothingStored(label, sdk, authEvents);
    }

    localStorage.clear();
    const { sdk, authEvents } = freshSdk();
    const error = await capture(() =>
      sdk.importFromSync(
        JSON.stringify({ ...backup, credential: { id: CREDENTIAL_ID, publicKey: otherPublicKey } })
      )
    );
    assert(
      error instanceof SyncBootstrapError && error.reason === "PUBLIC_KEY_MISMATCH",
      "altered public key: SyncBootstrapError PUBLIC_KEY_MISMATCH"
    );
    await assertNothingStored("altered public key", sdk, authEvents);

    const { prfSalt: _, ...noSalt } = backup;
    const parseError = await capture(() => freshSdk().sdk.importFromSync(JSON.stringify(noSalt)));
    assert(parseError instanceof Error, "PRF backup without prfSalt is rejected");
  }
  console.log("");

  console.log("Test 6: QR round trip");
  {
    const syncManager = new DeviceSyncManager();
    const qr = await syncManager.generateSyncQR(backup);
    assert(qr.startsWith("data:image/png;base64,"), "generateSyncQR returns a PNG data URL");
    assert(JSON.stringify(backup).length <= 2953, "payload fits in a QR code");

    const parsed = await syncManager.parseSyncQR(JSON.stringify(backup));
    assert(JSON.stringify(parsed) === JSON.stringify(backup), "parseSyncQR returns the same backup");

    localStorage.clear();
    const { sdk } = freshSdk();
    const result = await sdk.syncWalletWithPasskey(JSON.stringify(parsed));
    assert(result.mnemonic === MNEMONIC, "the parsed backup restores the wallet");
  }
  console.log("");

  console.log("Test 7: password fallback without PRF");
  {
    authenticator.prf = false;
    const sdk = await loggedInDeviceA(publicKey);
    const error = await capture(() => sdk.exportForSync());
    assert(error instanceof PrfUnsupportedError, "no password: throws PrfUnsupportedError");

    const fallback = await exportFromDeviceA(publicKey, PASSWORD);
    const file: BackupFile = JSON.parse(fallback.json);
    assert(file.encryptionMethod === "password", "with a password: emits a password backup");
    assert(file.credential?.id === CREDENTIAL_ID, "the password backup names the passkey");

    const importError = await capture(() => freshSdk().sdk.importFromSync(fallback.json));
    assert(importError instanceof WalletError, "importFromSync() points to syncWalletWithPasskey()");

    localStorage.clear();
    const { sdk: deviceB, authEvents } = freshSdk();
    const result = await deviceB.syncWalletWithPasskey(fallback.json, PASSWORD);
    assert(result.mnemonic === MNEMONIC, "syncWalletWithPasskey() restores it with the password");
    authenticator.prf = true;
    await assertSyncedAndLogsIn(deviceB, authEvents, publicKey);
  }
  console.log("");

  console.log("Test 8: importFromSync() refuses a backup of another passkey when logged in");
  {
    localStorage.clear();
    const { sdk } = freshSdk();
    (sdk as any).currentUser = {
      username: "bob",
      ethereumAddress: ADDRESS,
      credentialId: "another-passkey",
    };
    authenticator.calls = [];
    const error = await capture(() => sdk.importFromSync(json));
    assert(
      error instanceof SyncBootstrapError && error.reason === "CREDENTIAL_MISMATCH",
      "throws SyncBootstrapError CREDENTIAL_MISMATCH"
    );
    assert(authenticator.calls.length === 0, "before any prompt");
  }
  console.log("");

  console.log("==================================================");
  console.log(`✅ PRF Sync Tests: ${passed} passed, ${failed} failed`);
  console.log("==================================================\n");

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
