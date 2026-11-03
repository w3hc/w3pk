/**
 * restoreFromBackupFile() while logged in: the restored wallet replaces the
 * stored one only after the passkey assertion succeeds, and a different
 * address needs `allowAddressChange`
 *
 * Mocks navigator.credentials.get with a P-256 key that signs real
 * assertions, and a PRF computed as the spec describes,
 * HMAC-SHA256(credential secret, SHA-256("WebAuthn PRF" || 0x00 || input)).
 *
 * NOTE: the mnemonics are standard BIP39 test vectors, not real secrets
 */

import { Wallet } from "ethers";
import {
  Web3Passkey,
  AddressChangeError,
  AuthenticationError,
  PrfUnsupportedError,
} from "../src/index";
import { CredentialStorage } from "../src/auth/storage";
import { LocalStorageWalletStorage } from "../src/wallet/storage";
import { decryptData, deriveWalletKey, encryptData, PRF_INPUT } from "../src/wallet/crypto";
import { BackupFileManager, generatePrfSalt, prfSyncInput } from "../src/backup/backup-file";
import { arrayBufferToBase64Url } from "../src/utils/base64";

console.log("\n==================================================");
console.log("🔐 Restore Replacing a Wallet Test");
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
const PASSWORD = "TestStrongPass123!NotReal";
const CREDENTIAL_ID = arrayBufferToBase64Url(
  crypto.getRandomValues(new Uint8Array(16)).buffer
);
const MNEMONIC_A =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const MNEMONIC_B = "test test test test test test test test test test test junk";
const ADDRESS_A = Wallet.fromPhrase(MNEMONIC_A).address;
const ADDRESS_B = Wallet.fromPhrase(MNEMONIC_B).address;

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
  calls: 0,
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
          authenticator.calls++;
          if (!authenticator.available) {
            throw Object.assign(new Error("Cancelled"), { name: "NotAllowedError" });
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
            JSON.stringify({
              type: "webauthn.get",
              challenge: arrayBufferToBase64Url(publicKey.challenge as ArrayBuffer),
              origin: `http://${RP_ID}`,
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

          const inputs = (publicKey.extensions as any)?.prf?.eval;
          const first =
            authenticator.prf && inputs?.first ? await prf(authenticator.secret, inputs.first) : undefined;
          const second =
            authenticator.prf && inputs?.second ? await prf(authenticator.secret, inputs.second) : undefined;

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
              first ? { prf: { results: second ? { first, second } : { first } } } : {},
          };
        },
      },
    },
  });

  return arrayBufferToBase64Url(spki);
}

const credentials = () => new CredentialStorage(localStorage as unknown as Storage);
const wallets = () => new LocalStorageWalletStorage(localStorage as unknown as Storage);

async function loggedInWith(publicKey: string, mnemonic: string): Promise<Web3Passkey> {
  localStorage.clear();
  const address = Wallet.fromPhrase(mnemonic).address;
  const now = new Date().toISOString();
  await credentials().saveCredential({
    id: CREDENTIAL_ID,
    publicKey,
    username: USERNAME,
    ethereumAddress: address,
    createdAt: now,
    lastUsed: now,
  });
  const key = await deriveWalletKey(await prf(authenticator.secret, PRF_INPUT));
  await wallets().store({
    ethereumAddress: address,
    encryptedMnemonic: await encryptData(mnemonic, key),
    credentialId: CREDENTIAL_ID,
    createdAt: now,
  });

  const sdk = new Web3Passkey();
  (sdk as any).currentUser = {
    username: USERNAME,
    ethereumAddress: address,
    credentialId: CREDENTIAL_ID,
  };
  authenticator.calls = 0;
  return sdk;
}

async function storedMnemonic(address: string): Promise<string | undefined> {
  const stored = await wallets().retrieve(address);
  if (!stored) return undefined;
  const key = await deriveWalletKey(await prf(authenticator.secret, PRF_INPUT));
  return decryptData(stored.encryptedMnemonic, key);
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

  async function assertKeepsWalletA(sdk: Web3Passkey) {
    assert((await storedMnemonic(ADDRESS_A)) === MNEMONIC_A, "wallet A stays stored");
    assert((await wallets().retrieve(ADDRESS_B)) === null, "wallet B isn't stored");
    assert(
      (await credentials().getCredentialById(CREDENTIAL_ID))?.ethereumAddress === ADDRESS_A,
      "the credential still points at wallet A"
    );
    assert(sdk.user?.ethereumAddress === ADDRESS_A, "the user keeps wallet A's address");
    assert((sdk as any).currentWallet === null, "no wallet is set in memory");
  }

  async function assertReplacedByB(sdk: Web3Passkey) {
    assert((await storedMnemonic(ADDRESS_B)) === MNEMONIC_B, "wallet B is stored under B's address");
    assert((await wallets().retrieve(ADDRESS_A)) === null, "wallet A is deleted");
    assert(
      (await credentials().getCredentialById(CREDENTIAL_ID))?.ethereumAddress === ADDRESS_B,
      "the credential points at wallet B"
    );
    assert(sdk.user?.ethereumAddress === ADDRESS_B, "the user has wallet B's address");
  }

  const publicKey = await setupAuthenticator();
  const manager = new BackupFileManager();
  const { json: backupB } = await manager.createPasswordBackup(MNEMONIC_B, PASSWORD);
  const { json: backupA } = await manager.createPasswordBackup(MNEMONIC_A, PASSWORD);

  console.log("Test 1: a cancelled prompt keeps wallet A and the credential address");
  {
    const sdk = await loggedInWith(publicKey, MNEMONIC_A);
    authenticator.available = false;
    const error = await capture(() =>
      sdk.restoreFromBackupFile(backupB, PASSWORD, { allowAddressChange: true })
    );
    authenticator.available = true;
    assert(error instanceof AuthenticationError, "throws AuthenticationError");
    assert(authenticator.calls === 1, "the prompt was shown");
    await assertKeepsWalletA(sdk);
  }
  console.log("");

  console.log("Test 2: an authenticator without PRF keeps wallet A");
  {
    const sdk = await loggedInWith(publicKey, MNEMONIC_A);
    authenticator.prf = false;
    const error = await capture(() =>
      sdk.restoreFromBackupFile(backupB, PASSWORD, { allowAddressChange: true })
    );
    authenticator.prf = true;
    assert(error instanceof PrfUnsupportedError, "throws PrfUnsupportedError");
    await assertKeepsWalletA(sdk);
  }
  console.log("");

  console.log("Test 3: a different address without allowAddressChange throws before the prompt");
  {
    const sdk = await loggedInWith(publicKey, MNEMONIC_A);
    const error = await capture(() => sdk.restoreFromBackupFile(backupB, PASSWORD));
    assert(error instanceof AddressChangeError, "throws AddressChangeError");
    assert(
      error instanceof AddressChangeError &&
        error.code === "ADDRESS_CHANGE_NOT_ALLOWED" &&
        error.currentAddress === ADDRESS_A &&
        error.newAddress === ADDRESS_B,
      "names both addresses"
    );
    assert(authenticator.calls === 0, "no passkey prompt");
    await assertKeepsWalletA(sdk);
  }
  console.log("");

  console.log("Test 4: with allowAddressChange, wallet B replaces wallet A");
  {
    const sdk = await loggedInWith(publicKey, MNEMONIC_A);
    const result = await sdk.restoreFromBackupFile(backupB, PASSWORD, { allowAddressChange: true });
    assert(result.ethereumAddress === ADDRESS_B, "returns wallet B's address");
    assert(authenticator.calls === 1, "one passkey prompt");
    await assertReplacedByB(sdk);
  }
  console.log("");

  console.log("Test 5: the same address restores without allowAddressChange");
  {
    const sdk = await loggedInWith(publicKey, MNEMONIC_A);
    const result = await sdk.restoreFromBackupFile(backupA, PASSWORD);
    assert(result.ethereumAddress === ADDRESS_A, "returns wallet A's address");
    assert((await storedMnemonic(ADDRESS_A)) === MNEMONIC_A, "wallet A stays stored");
    assert(sdk.user?.ethereumAddress === ADDRESS_A, "the user keeps wallet A's address");
  }
  console.log("");

  console.log("Test 6: a PRF backup of another address than the stored one");
  {
    const prfSalt = generatePrfSalt();
    const { json: prfBackupB } = await manager.createPrfBackup(
      MNEMONIC_B,
      { id: CREDENTIAL_ID, publicKey },
      USERNAME,
      prfSalt,
      await prf(authenticator.secret, await prfSyncInput(prfSalt))
    );

    const sdk = await loggedInWith(publicKey, MNEMONIC_A);
    const error = await capture(() => sdk.restoreFromBackupFile(prfBackupB));
    assert(error instanceof AddressChangeError, "without allowAddressChange, throws AddressChangeError");
    await assertKeepsWalletA(sdk);

    const replaced = await loggedInWith(publicKey, MNEMONIC_A);
    await replaced.restoreFromBackupFile(prfBackupB, undefined, { allowAddressChange: true });
    await assertReplacedByB(replaced);
  }
  console.log("");

  console.log("==================================================");
  console.log(`✅ Restore Replacing a Wallet Tests: ${passed} passed, ${failed} failed`);
  console.log("==================================================\n");

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
