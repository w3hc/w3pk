/**
 * getSemaphoreIdentity(tag)
 *
 * Same mocked PRF authenticator as prf-secret.test.ts. The expected private
 * key is recomputed here from the credential secret, so the commitment can
 * be checked against @semaphore-protocol/identity.
 *
 * NOTE: the mnemonic is the standard BIP39 test vector, not a real secret
 */

import { Wallet } from "ethers";
import { Identity } from "@semaphore-protocol/identity";
import {
  Web3Passkey,
  PrfUnsupportedError,
  CryptoError,
} from "../src/index";
import { babyJubPublicKey } from "../src/zk/babyjub";
import { loadSemaphoreCommitment } from "../src/zk/semaphore";
import { CredentialStorage } from "../src/auth/storage";
import { arrayBufferToBase64Url } from "../src/utils/base64";

console.log("\n==================================================");
console.log("🪪 Semaphore Identity Test");
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

async function expectedPrivateKey(
  credentialId: string,
  origin: string,
  tag: string
): Promise<Uint8Array> {
  const context = new TextEncoder().encode(`w3pk-semaphore-v1:${origin}:${tag}`);
  const output = await prf(
    credentialSecrets.get(credentialId)!,
    await crypto.subtle.digest("SHA-256", context)
  );
  const key = await crypto.subtle.importKey("raw", output, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new TextEncoder().encode("w3pk-prf-secret-v1"),
      info: context,
    },
    key,
    256
  );
  return new Uint8Array(bits);
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

  const ORIGIN = `http://${RP_ID}`;

  console.log("Test 1: the commitment matches @semaphore-protocol/identity");
  {
    reset();
    const sdk = new Web3Passkey();
    const a = await sdk.getSemaphoreIdentity("voting");
    const b = await sdk.getSemaphoreIdentity("voting");
    const identity = new Identity(await expectedPrivateKey(CRED_A, ORIGIN, "voting"));
    assert(typeof a.commitment === "bigint", "commitment is a bigint");
    assert(a.commitment === identity.commitment, "equals new Identity(privateKey).commitment");
    assert(a.commitment === b.commitment, "commitment is deterministic");
    assert(a.credentialId === CRED_A, "returns the credential it used");

    const [x, y] = babyJubPublicKey(identity.secretScalar);
    assert(
      x === identity.publicKey[0] && y === identity.publicKey[1],
      "the identity's public key is secretScalar · Base8 in w3pk/zk"
    );

    const fixed = new Uint8Array(32).map((_, i) => i);
    assert(
      (await loadSemaphoreCommitment())(fixed) ===
        4012409914446104931572884973054117983812319938681427071249351666971656642037n,
      "fixed vector: private key 0x00..1f"
    );
    assert(fixed.every((byte) => byte === 0), "the private key is zeroed after use");
  }
  console.log("");

  console.log("Test 2: a different tag or origin gives a different commitment");
  {
    reset();
    const sdk = new Web3Passkey();
    const base = await sdk.getSemaphoreIdentity("voting");
    const otherTag = await sdk.getSemaphoreIdentity("posting");
    assert(base.commitment !== otherTag.commitment, "different tag");

    location.origin = `http://${RP_ID}:3000`;
    const otherOrigin = await sdk.getSemaphoreIdentity("voting");
    assert(base.commitment !== otherOrigin.commitment, "different origin, same RP ID");
  }
  console.log("");

  console.log("Test 3: a new credential gives a new commitment and reports it");
  {
    reset();
    const before = await new Web3Passkey().getSemaphoreIdentity("voting");
    authenticator.selected = CRED_B;
    const after = await new Web3Passkey().getSemaphoreIdentity("voting");
    assert(after.credentialId === CRED_B, "reports the new credential");
    assert(after.credentialId !== before.credentialId, "credentialId changes with the credential");
    assert(after.commitment !== before.commitment, "commitment changes with the credential");

    authenticator.selected = CRED_A;
    authenticator.calls = [];
    const result = await loggedInSdk(CRED_B).getSemaphoreIdentity("voting");
    const allowed = authenticator.calls[0].allowCredentials ?? [];
    assert(
      allowed.length === 1 &&
        arrayBufferToBase64Url(allowed[0].id as ArrayBuffer) === CRED_B,
      "logged in: restricted to the current user's passkey"
    );
    assert(result.commitment === after.commitment, "logged in: the current user's identity");
  }
  console.log("");

  console.log("Test 4: derivePrfSecret(tag) can't reach the identity's private key");
  {
    reset();
    const sdk = new Web3Passkey();
    await sdk.getSemaphoreIdentity("voting");
    const expected = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(`w3pk-semaphore-v1:${ORIGIN}:voting`)
    );
    const first = (authenticator.calls[0].extensions as any).prf.eval.first as ArrayBuffer;
    assert(
      hex(new Uint8Array(first)) === hex(new Uint8Array(expected)),
      "PRF input is SHA-256(w3pk-semaphore-v1:origin:tag)"
    );

    const { commitment } = await sdk.getSemaphoreIdentity("voting");
    const { secret } = await sdk.derivePrfSecret("voting");
    const privateKey = await expectedPrivateKey(CRED_A, ORIGIN, "voting");
    assert(hex(secret) !== hex(privateKey), "derivePrfSecret(tag) returns a different secret");
    assert(
      new Identity(secret).commitment !== commitment,
      "an identity built from derivePrfSecret(tag) has another commitment"
    );
  }
  console.log("");

  console.log("Test 5: the private key is neither returned nor stored");
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
    const result = await sdk.getSemaphoreIdentity("voting");
    assert(
      JSON.stringify(Object.keys(result).sort()) === '["commitment","credentialId"]',
      "the result has only commitment and credentialId"
    );
    assert(snapshot() === before, "localStorage is unchanged");
    assert(!sdk.hasActiveSession(), "no session is started");

    const privateKey = await expectedPrivateKey(CRED_A, ORIGIN, "voting");
    const identity = new Identity(privateKey);
    const serialized = JSON.stringify(result, (_, v) =>
      typeof v === "bigint" ? v.toString() : v
    );
    const secrets = [
      ...encodings(privateKey),
      identity.export(),
      identity.secretScalar.toString(),
      identity.secretScalar.toString(16),
    ];
    const { blob } = await sdk.createBackupFile(PASSWORD);
    const backup = await blob.text();
    const stored = snapshot();
    const leaks = secrets.filter(
      (e) => serialized.includes(e) || backup.includes(e) || stored.includes(e)
    );
    assert(leaks.length === 0, "the private key is in neither the result, the backup file nor storage");
  }
  console.log("");

  console.log("Test 6: errors");
  {
    reset();
    authenticator.prf = false;
    const errors: unknown[] = [];
    const sdk = new Web3Passkey({ onError: (e) => errors.push(e) });
    const error = await capture(() => sdk.getSemaphoreIdentity("voting"));
    assert(error instanceof PrfUnsupportedError, "no PRF support throws PrfUnsupportedError");
    assert(errors[0] === error, "reports it to onError");

    authenticator.prf = true;
    authenticator.calls = [];
    for (const tag of ["", "a:b"]) {
      const invalid = await capture(() => sdk.getSemaphoreIdentity(tag));
      assert(invalid instanceof CryptoError, `rejects tag ${JSON.stringify(tag)}`);
    }
    assert(authenticator.calls.length === 0, "no prompt for an invalid tag");
  }
  console.log("");

  console.log("==================================================");
  console.log(
    `${failed === 0 ? "✅" : "❌"} Semaphore Identity Tests: ${passed} passed, ${failed} failed`
  );
  console.log("==================================================\n");
  if (failed > 0) process.exit(1);
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
