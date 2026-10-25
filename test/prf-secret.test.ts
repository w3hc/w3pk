/**
 * derivePrfSecret(tag) and the evaluatePrf helper
 *
 * Mocks navigator.credentials.get with an authenticator that computes the
 * PRF as the spec describes: HMAC-SHA256(credential secret,
 * SHA-256("WebAuthn PRF" || 0x00 || input)).
 *
 * NOTE: the mnemonic is the standard BIP39 test vector, not a real secret
 */

import { Wallet } from "ethers";
import {
  Web3Passkey,
  PrfUnsupportedError,
  AuthenticationError,
  CryptoError,
  Web3PasskeyError,
} from "../src/index";
import { CredentialStorage } from "../src/auth/storage";
import { arrayBufferToBase64Url } from "../src/utils/base64";

console.log("\n==================================================");
console.log("🔑 PRF Secret Test");
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
const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ADDRESS = Wallet.fromPhrase(MNEMONIC).address;

const localStorage = new MemoryStorage();
(globalThis as any).localStorage = localStorage;
const location = { hostname: RP_ID, origin: `http://${RP_ID}` };
(globalThis as any).window = { location, localStorage };

function randomId(): string {
  return arrayBufferToBase64Url(crypto.getRandomValues(new Uint8Array(16)).buffer);
}

const CRED_A = randomId();
const CRED_B = randomId();
const credentialSecrets = new Map<string, Uint8Array>([
  [CRED_A, crypto.getRandomValues(new Uint8Array(32))],
  [CRED_B, crypto.getRandomValues(new Uint8Array(32))],
]);

const authenticator = {
  selected: CRED_A,
  prf: true,
  reject: null as Error | null,
  calls: [] as PublicKeyCredentialRequestOptions[],
};

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

Object.defineProperty(globalThis, "navigator", {
  configurable: true,
  value: {
    userAgent: "node",
    credentials: {
      get: async ({ publicKey }: { publicKey: PublicKeyCredentialRequestOptions }) => {
        authenticator.calls.push(publicKey);
        if (authenticator.reject) throw authenticator.reject;

        const allowed = (publicKey.allowCredentials ?? []).map((c) =>
          arrayBufferToBase64Url(c.id as ArrayBuffer)
        );
        const id = allowed.length > 0 ? allowed[0] : authenticator.selected;
        const input = (publicKey.extensions as any)?.prf?.eval?.first;
        const first =
          authenticator.prf && input
            ? await prf(credentialSecrets.get(id)!, input)
            : undefined;

        return {
          id,
          rawId: new Uint8Array(16).buffer,
          type: "public-key",
          response: {
            authenticatorData: new Uint8Array(37).buffer,
            clientDataJSON: new Uint8Array(0).buffer,
            signature: new Uint8Array(0).buffer,
          },
          getClientExtensionResults: () =>
            first ? { prf: { results: { first } } } : {},
        };
      },
    },
  },
});

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function encodings(bytes: Uint8Array): string[] {
  const b64 = Buffer.from(bytes).toString("base64");
  return [
    hex(bytes),
    b64,
    b64.replace(/=+$/, ""),
    arrayBufferToBase64Url(bytes.slice().buffer),
    JSON.stringify(Array.from(bytes)).slice(1, -1),
  ];
}

function snapshot(): string {
  const entries: string[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i)!;
    entries.push(`${k}=${localStorage.getItem(k)}`);
  }
  return entries.sort().join("\n");
}

function loggedInSdk(credentialId: string): Web3Passkey {
  const sdk = new Web3Passkey();
  (sdk as any).currentUser = {
    username: USERNAME,
    ethereumAddress: ADDRESS,
    credentialId,
  };
  (sdk as any).getMnemonicFromSession = async () => MNEMONIC;
  return sdk;
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

  function reset() {
    authenticator.selected = CRED_A;
    authenticator.prf = true;
    authenticator.reject = null;
    authenticator.calls = [];
    location.origin = `http://${RP_ID}`;
  }

  console.log("Test 1: same credential, origin and tag give the same secret");
  {
    reset();
    const sdk = new Web3Passkey();
    const a = await sdk.derivePrfSecret("zk-identity");
    const b = await sdk.derivePrfSecret("zk-identity");
    assert(a.secret instanceof Uint8Array, "secret is a Uint8Array");
    assert(a.secret.length === 32, "secret is 32 bytes");
    assert(hex(a.secret) === hex(b.secret), "secret is deterministic");
    assert(a.credentialId === CRED_A, "returns the credential it used");
  }
  console.log("");

  console.log("Test 2: a different tag, origin or credential gives a different secret");
  {
    reset();
    const sdk = new Web3Passkey();
    const base = await sdk.derivePrfSecret("zk-identity");
    const otherTag = await sdk.derivePrfSecret("encryption");
    assert(hex(base.secret) !== hex(otherTag.secret), "different tag");

    location.origin = `http://${RP_ID}:3000`;
    const otherOrigin = await sdk.derivePrfSecret("zk-identity");
    assert(hex(base.secret) !== hex(otherOrigin.secret), "different origin, same RP ID");
    location.origin = `http://${RP_ID}`;

    authenticator.selected = CRED_B;
    const otherCred = await sdk.derivePrfSecret("zk-identity");
    assert(otherCred.credentialId === CRED_B, "reports the other credential");
    assert(hex(base.secret) !== hex(otherCred.secret), "different credential");

    const upper = await new Web3Passkey().derivePrfSecret("ZK-IDENTITY");
    assert(hex(upper.secret) !== hex(otherCred.secret), "tags are case-sensitive");
  }
  console.log("");

  console.log("Test 3: the assertion requests the PRF on a user-verified assertion");
  {
    reset();
    await new Web3Passkey().derivePrfSecret("zk-identity");
    const options = authenticator.calls[0];
    assert(options.userVerification === "required", "userVerification is required");
    assert(options.rpId === RP_ID, "rpId is the hostname");
    const expected = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(`w3pk-prf-v1:http://${RP_ID}:zk-identity`)
    );
    const first = (options.extensions as any).prf.eval.first as ArrayBuffer;
    assert(
      hex(new Uint8Array(first)) === hex(new Uint8Array(expected)),
      "PRF input is SHA-256(w3pk-prf-v1:origin:tag)"
    );
    assert(!options.allowCredentials, "logged out: any passkey can be picked");

    authenticator.calls = [];
    const result = await loggedInSdk(CRED_B).derivePrfSecret("zk-identity");
    const allowed = authenticator.calls[0].allowCredentials ?? [];
    assert(
      allowed.length === 1 &&
        arrayBufferToBase64Url(allowed[0].id as ArrayBuffer) === CRED_B,
      "logged in: restricted to the current user's passkey"
    );
    assert(result.credentialId === CRED_B, "logged in: uses the current user's passkey");
  }
  console.log("");

  console.log("Test 4: no PRF support throws PrfUnsupportedError");
  {
    reset();
    authenticator.prf = false;
    const errors: unknown[] = [];
    const sdk = new Web3Passkey({ onError: (e) => errors.push(e) });
    const error = await capture(() => sdk.derivePrfSecret("zk-identity"));
    assert(error instanceof PrfUnsupportedError, "throws PrfUnsupportedError");
    assert(error instanceof Web3PasskeyError, "extends Web3PasskeyError");
    assert((error as PrfUnsupportedError).code === "PRF_UNSUPPORTED", "has code PRF_UNSUPPORTED");
    assert((error as PrfUnsupportedError).credentialId === CRED_A, "names the credential");
    assert(errors[0] === error, "reports it to onError");
  }
  console.log("");

  console.log("Test 5: invalid tags and cancelled prompts");
  {
    reset();
    const sdk = new Web3Passkey();
    for (const tag of ["", "8080:zk-identity"]) {
      const error = await capture(() => sdk.derivePrfSecret(tag));
      assert(error instanceof CryptoError, `rejects tag ${JSON.stringify(tag)}`);
    }
    assert(authenticator.calls.length === 0, "no prompt for an invalid tag");

    authenticator.reject = Object.assign(new Error("cancelled"), {
      name: "NotAllowedError",
    });
    const error = await capture(() => sdk.derivePrfSecret("zk-identity"));
    assert(error instanceof AuthenticationError, "a cancelled prompt throws AuthenticationError");
  }
  console.log("");

  console.log("Test 6: the secret never reaches storage, sessions or backups");
  {
    reset();
    localStorage.clear();
    const now = new Date().toISOString();
    await new CredentialStorage(localStorage as unknown as Storage).saveCredential({
      id: CRED_A,
      publicKey: "unused",
      username: USERNAME,
      ethereumAddress: ADDRESS,
      createdAt: now,
      lastUsed: now,
    });

    const sdk = loggedInSdk(CRED_A);
    const before = snapshot();
    const { secret } = await sdk.derivePrfSecret("zk-identity");
    assert(snapshot() === before, "localStorage is unchanged");
    assert(!sdk.hasActiveSession(), "no session is started");

    const { blob } = await sdk.createBackupFile("password", PASSWORD);
    const backup = await blob.text();
    const stored = snapshot();
    const leaks = encodings(secret).filter(
      (e) => backup.includes(e) || stored.includes(e)
    );
    assert(leaks.length === 0, "secret is in neither the backup file nor storage");
  }
  console.log("");

  console.log("==================================================");
  console.log(`✅ PRF Secret Tests: ${passed} passed, ${failed} failed`);
  console.log("==================================================\n");

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
