/**
 * userVerification option: any authenticator at registration, the configured
 * requirement on login, registration and signing, PRF calls always verified,
 * and PRF output ignored when the authenticator data's UV flag is clear
 *
 * NOTE: the mnemonic is the standard BIP39 test vector, not a real secret
 */

import { Wallet } from "ethers";
import { Web3Passkey } from "../src/index";
import { register } from "../src/auth/register";
import { login } from "../src/auth/authenticate";
import { isUserVerified } from "../src/auth/flags";
import { CredentialStorage } from "../src/auth/storage";
import { LocalStorageWalletStorage } from "../src/wallet/storage";
import { deriveEncryptionKeyFromWebAuthn, encryptData } from "../src/wallet/crypto";
import { arrayBufferToBase64Url } from "../src/utils/base64";

console.log("\n==================================================");
console.log("🔐 User Verification Test");
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
  flags: UP | UV,
  prfOutput: crypto.getRandomValues(new Uint8Array(32)).buffer,
  createCalls: [] as PublicKeyCredentialCreationOptions[],
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
async function attestationObject(publicKeyRaw: Uint8Array, flags: number): Promise<ArrayBuffer> {
  const x = publicKeyRaw.slice(1, 33);
  const y = publicKeyRaw.slice(33, 65);
  const cose = [0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, ...x, 0x22, 0x58, 0x20, ...y];
  const credId = new Uint8Array(16);
  const authData = [
    ...(await rpIdHash()),
    flags | AT,
    0, 0, 0, 0,
    ...new Uint8Array(16),
    0, credId.length,
    ...credId,
    ...cose,
  ];
  const authDataKey = [0x68, ...new TextEncoder().encode("authData")];
  return new Uint8Array([
    0xa3,
    ...authDataKey,
    0x59, authData.length >> 8, authData.length & 0xff,
    ...authData,
  ]).buffer;
}

async function setupAuthenticator(): Promise<string> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  let signCount = 0;

  const prfResults = (extensions: any) =>
    extensions?.prf?.eval?.first ? { prf: { results: { first: authenticator.prfOutput } } } : {};

  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: {
      userAgent: "node",
      credentials: {
        create: async ({ publicKey }: { publicKey: PublicKeyCredentialCreationOptions }) => {
          authenticator.createCalls.push(publicKey);
          return {
            id: CREDENTIAL_ID,
            rawId: new Uint8Array(16).buffer,
            type: "public-key",
            response: {
              attestationObject: await attestationObject(raw, authenticator.flags),
              clientDataJSON: new ArrayBuffer(0),
            },
            getClientExtensionResults: () => prfResults(publicKey.extensions),
          };
        },
        get: async ({ publicKey }: { publicKey: PublicKeyCredentialRequestOptions }) => {
          authenticator.getCalls.push(publicKey);

          signCount++;
          const authenticatorData = new Uint8Array(37);
          authenticatorData.set(await rpIdHash(), 0);
          authenticatorData[32] = authenticator.flags;
          new DataView(authenticatorData.buffer).setUint32(33, signCount);

          const clientDataJSON = new TextEncoder().encode(
            JSON.stringify({ type: "webauthn.get", origin: `http://${RP_ID}` })
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
            getClientExtensionResults: () => prfResults(publicKey.extensions),
          };
        },
      },
    },
  });

  return arrayBufferToBase64Url(spki);
}

async function storeWallet(publicKey: string): Promise<void> {
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
}

function reset(flags: number) {
  authenticator.flags = flags;
  authenticator.createCalls = [];
  authenticator.getCalls = [];
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

  console.log("Test 1: isUserVerified reads bit 2 of the flags byte");
  {
    const authData = new Uint8Array(37);
    authData[32] = UP | UV;
    assert(isUserVerified(authData), "UP|UV is verified");
    authData[32] = UP;
    assert(!isUserVerified(authData), "UP alone is not verified");
    assert(!isUserVerified(new Uint8Array(32)), "truncated authenticator data is not verified");
  }
  console.log("");

  console.log("Test 2: registration accepts any authenticator");
  {
    localStorage.clear();
    reset(UP | UV);
    const result = await register({ username: USERNAME, ethereumAddress: ADDRESS });
    const selection = authenticator.createCalls[0].authenticatorSelection!;
    assert(!("authenticatorAttachment" in selection), "no authenticatorAttachment");
    assert(selection.residentKey === "required", "residentKey stays required");
    assert(selection.userVerification === "required", "userVerification defaults to required");
    assert(result.prfOutput !== undefined, "verified registration returns the PRF output");
  }
  console.log("");

  console.log("Test 3: registration with userVerification 'preferred'");
  {
    localStorage.clear();
    reset(UP);
    const result = await register({
      username: USERNAME,
      ethereumAddress: ADDRESS,
      userVerification: "preferred",
    });
    assert(
      authenticator.createCalls[0].authenticatorSelection!.userVerification === "preferred",
      "userVerification reaches the creation options"
    );
    assert(result.prfOutput === undefined, "unverified registration drops the PRF output");
  }
  console.log("");

  console.log("Test 4: login with userVerification 'preferred'");
  {
    await storeWallet(publicKey);
    reset(UP | UV);
    const verified = await login("preferred");
    assert(authenticator.getCalls[0].userVerification === "preferred", "reaches the request options");
    assert(verified.prfOutput !== undefined, "verified login returns the PRF output");

    reset(UP);
    const unverified = await login("preferred");
    assert(unverified.verified, "unverified login still succeeds");
    assert(unverified.prfOutput === undefined, "unverified login drops the PRF output");

    reset(UP | UV);
    await login();
    assert(authenticator.getCalls[0].userVerification === "required", "defaults to required");
  }
  console.log("");

  console.log("Test 5: the SDK passes the config to login and signing");
  {
    await storeWallet(publicKey);
    reset(UP);
    const sdk = new Web3Passkey({ userVerification: "preferred" });
    await sdk.login();
    assert(sdk.isAuthenticated, "unverified login opens the wallet");
    assert(
      authenticator.getCalls.every((c) => c.userVerification === "preferred"),
      "login() requests 'preferred'"
    );

    reset(UP);
    try {
      await sdk.signMessageWithPasskey("hello");
    } catch {
      // only the request options matter here
    }
    assert(
      authenticator.getCalls[0]?.userVerification === "preferred",
      "signMessageWithPasskey() requests 'preferred'"
    );

    await storeWallet(publicKey);
    reset(UP | UV);
    const strict = new Web3Passkey();
    await strict.login();
    assert(
      authenticator.getCalls.every((c) => c.userVerification === "required"),
      "the default config requests 'required'"
    );
  }
  console.log("");

  console.log("Test 6: PRF calls stay required with 'preferred'");
  {
    await storeWallet(publicKey);
    reset(UP | UV);
    const sdk = new Web3Passkey({ userVerification: "preferred" });
    await sdk.login();
    reset(UP | UV);
    await sdk.derivePrfSecret("zk-identity");
    assert(authenticator.getCalls.length === 1, "one assertion");
    assert(
      authenticator.getCalls[0].userVerification === "required",
      "derivePrfSecret() requests 'required'"
    );
  }
  console.log("");

  console.log("==================================================");
  console.log(`✅ User Verification Tests: ${passed} passed, ${failed} failed`);
  console.log("==================================================\n");

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
