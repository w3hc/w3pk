/**
 * zkProve(tag, artifacts, publicInputs, extraWitness, options)
 *
 * Same mocked PRF authenticator as prf-secret.test.ts. Proves with the
 * prebuilt circuit in fixtures/zk-prove (see its .circom): commitment =
 * Poseidon(secret), nullifier = Poseidon(contextSecret) with contextSecret =
 * Poseidon(secret, scope, 1), blinded = Poseidon(message, r). The expected
 * secrets are recomputed here from the credential secret.
 *
 * NOTE: the mnemonic is the standard BIP39 test vector, not a real secret
 */

import { readFileSync } from "fs";
import { join } from "path";
import { Wallet } from "ethers";
import { Identity } from "@semaphore-protocol/identity";
import { poseidon1, poseidon2, poseidon3 } from "poseidon-lite";
import {
  Web3Passkey,
  CryptoError,
  ZkArtifactMismatchError,
  type ZkProveOptions,
} from "../../src/index";
import { deriveBabyJubKeyPair, BABYJUB_SUBORDER } from "../../src/zk/babyjub";
import { CredentialStorage } from "../../src/auth/storage";
import { arrayBufferToBase64Url } from "../../src/utils/base64";

console.log("\n==================================================");
console.log("🧾 zkProve Test");
console.log("==================================================\n");

const FIXTURES = join(__dirname, "fixtures", "zk-prove");
const WASM = new Uint8Array(readFileSync(join(FIXTURES, "zk-prove.wasm")));
const ZKEY = new Uint8Array(readFileSync(join(FIXTURES, "zk-prove.zkey")));
const VKEY = JSON.parse(readFileSync(join(FIXTURES, "zk-prove.vkey.json"), "utf8"));
const PINS = {
  wasm: "bafybeigzucvscal4ibxoweyveu5npfdr5udmy3w3yj7sdzqrwubwkgwnta",
  zkey: "bafybeihonziqpjk2hoau5nhb5bi5v4lmbnrd6da676hnvvvze7bvls7gbu",
};
const ARTIFACTS = { wasm: WASM, zkey: ZKEY, pins: PINS };
const OPTIONS: ZkProveOptions = {
  derive: { contextSecret: ["secret", "scope", 1n] },
  random: ["r"],
};

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

async function expectedPrfSecret(
  label: string,
  credentialId: string,
  origin: string,
  tag: string
): Promise<Uint8Array> {
  const context = new TextEncoder().encode(`${label}:${origin}:${tag}`);
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

async function expectedZkSecret(credentialId: string, origin: string, tag: string): Promise<bigint> {
  return deriveBabyJubKeyPair(await expectedPrfSecret("w3pk-zk-v1", credentialId, origin, tag))
    .privateKey;
}

async function expectedSemaphoreSecret(credentialId: string, origin: string, tag: string): Promise<bigint> {
  return new Identity(await expectedPrfSecret("w3pk-semaphore-v1", credentialId, origin, tag))
    .secretScalar;
}

// Records every 64-byte draw, the size randomBabyJubScalar() takes, as the
// scalar it maps to: (big-endian value mod (l - 1)) + 1
const draws: bigint[] = [];
const getRandomValues = crypto.getRandomValues.bind(crypto);
(crypto as any).getRandomValues = <T extends ArrayBufferView | null>(array: T): T => {
  const result = getRandomValues(array as any) as T;
  if (array instanceof Uint8Array && array.length === 64) {
    let value = 0n;
    for (const byte of array) value = (value << 8n) | BigInt(byte);
    draws.push((value % (BABYJUB_SUBORDER - 1n)) + 1n);
  }
  return result;
};

async function capture(fn: () => Promise<unknown>): Promise<unknown> {
  try {
    await fn();
  } catch (e) {
    return e;
  }
  return undefined;
}

async function verify(result: { proof: unknown; publicSignals: string[] }): Promise<boolean> {
  const snarkjs = await import("snarkjs");
  return snarkjs.groth16.verify(VKEY, result.publicSignals, result.proof);
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
  }

  const ORIGIN = `http://${RP_ID}`;
  const SCOPE = 42n;
  const MESSAGE = 7n;

  console.log("Test 1: a valid proof using the zk secret, a derived and a random input");
  {
    reset();
    const sdk = new Web3Passkey();
    const result = await sdk.zkProve("voting", ARTIFACTS, { scope: SCOPE }, { message: MESSAGE }, OPTIONS);
    assert(
      JSON.stringify(Object.keys(result).sort()) === '["proof","publicSignals"]',
      "the result has only proof and publicSignals"
    );
    assert(await verify(result), "the proof verifies against the verification key");

    const secret = await expectedZkSecret(CRED_A, ORIGIN, "voting");
    const [commitment, nullifier, blinded, scope] = result.publicSignals;
    assert(commitment === poseidon1([secret]).toString(), "the circuit received the zk secret");
    assert(
      nullifier === poseidon1([poseidon3([secret, SCOPE, 1n])]).toString(),
      "contextSecret = Poseidon(secret, scope, 1), computed in w3pk"
    );
    assert(scope === SCOPE.toString(), "the public input is a public signal");

    const again = await sdk.zkProve("voting", ARTIFACTS, { scope: SCOPE }, { message: MESSAGE }, OPTIONS);
    assert(again.publicSignals[0] === commitment, "the secret is deterministic");
    assert(again.publicSignals[2] !== blinded, "the random input is fresh on each call");

    const expected = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(`w3pk-zk-v1:${ORIGIN}:voting`)
    );
    const first = (authenticator.calls[0].extensions as any).prf.eval.first as ArrayBuffer;
    assert(
      Buffer.from(first).equals(Buffer.from(expected)),
      "PRF input is SHA-256(w3pk-zk-v1:origin:tag)"
    );
    assert(authenticator.calls.length === 2, "one passkey prompt per proof");
  }
  console.log("");

  console.log("Test 2: the Semaphore identity's secretScalar as the secret");
  {
    reset();
    const result = await new Web3Passkey().zkProve(
      "voting",
      ARTIFACTS,
      { scope: SCOPE },
      { message: MESSAGE },
      { ...OPTIONS, secret: "semaphore" }
    );
    const secret = await expectedSemaphoreSecret(CRED_A, ORIGIN, "voting");
    assert(await verify(result), "the proof verifies");
    assert(
      result.publicSignals[0] === poseidon1([secret]).toString(),
      "the circuit received the identity's secretScalar"
    );
    assert(
      result.publicSignals[0] !==
        poseidon1([await expectedZkSecret(CRED_A, ORIGIN, "voting")]).toString(),
      "the Semaphore and zk secrets differ"
    );
  }
  console.log("");

  console.log("Test 3: secret, derived and random values are neither returned nor stored");
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
    draws.length = 0;
    const result = await sdk.zkProve("voting", ARTIFACTS, { scope: SCOPE }, { message: MESSAGE }, OPTIONS);
    assert(snapshot() === before, "localStorage is unchanged");

    const r = draws.find((d) => poseidon2([MESSAGE, d]).toString() === result.publicSignals[2]);
    assert(r !== undefined, "the random input is recovered from the test's RNG hook");

    const prfSecret = await expectedPrfSecret("w3pk-zk-v1", CRED_A, ORIGIN, "voting");
    const secret = await expectedZkSecret(CRED_A, ORIGIN, "voting");
    const contextSecret = poseidon3([secret, SCOPE, 1n]);
    const values = [secret, contextSecret, r ?? 0n];
    const secrets = [
      ...encodings(prfSecret),
      ...values.flatMap((v) => [v.toString(), v.toString(16)]),
    ];
    const serialized = JSON.stringify(result);
    const { blob } = await sdk.createBackupFile(PASSWORD);
    const backup = await blob.text();
    const stored = snapshot();
    const leaks = secrets.filter(
      (e) => serialized.includes(e) || backup.includes(e) || stored.includes(e)
    );
    assert(leaks.length === 0, "none is in the result, the backup file or storage");

    const { secret: publicSecret } = await sdk.derivePrfSecret("voting");
    assert(
      Buffer.from(publicSecret).toString("hex") !== Buffer.from(prfSecret).toString("hex"),
      "derivePrfSecret(tag) can't return the zk secret"
    );
  }
  console.log("");

  console.log("Test 4: artifacts failing verification are rejected before the prompt");
  {
    reset();
    const tampered = WASM.slice();
    tampered[tampered.length - 1] ^= 1;
    const error = await capture(() =>
      new Web3Passkey().zkProve("voting", { ...ARTIFACTS, wasm: tampered }, { scope: SCOPE }, { message: MESSAGE }, OPTIONS)
    );
    assert(error instanceof ZkArtifactMismatchError, "a tampered wasm throws ZkArtifactMismatchError");

    const wrongPin = await capture(() =>
      new Web3Passkey().zkProve(
        "voting",
        { ...ARTIFACTS, pins: { ...PINS, zkey: PINS.wasm } },
        { scope: SCOPE },
        { message: MESSAGE },
        OPTIONS
      )
    );
    assert(wrongPin instanceof ZkArtifactMismatchError, "a wrong pin throws ZkArtifactMismatchError");
    assert(authenticator.calls.length === 0, "no passkey prompt");
  }
  console.log("");

  console.log("Test 5: a circuit making the secret public gets no proof");
  {
    reset();
    const error = await capture(() =>
      new Web3Passkey().zkProve(
        "voting",
        ARTIFACTS,
        {},
        { secret: 1n, message: MESSAGE },
        { secretInput: "scope", derive: { contextSecret: ["secret", "scope", 1n] }, random: ["r"] }
      )
    );
    assert(
      error instanceof CryptoError && /public/.test(error.message),
      "the secret in the public signals is refused"
    );
  }
  console.log("");

  console.log("Test 6: invalid calls fail before the prompt");
  {
    reset();
    const errors: unknown[] = [];
    const sdk = new Web3Passkey({ onError: (e) => errors.push(e) });
    const cases: [string, () => Promise<unknown>][] = [
      ["empty tag", () => sdk.zkProve("", ARTIFACTS, { scope: SCOPE }, { message: MESSAGE }, OPTIONS)],
      ["tag with ':'", () => sdk.zkProve("a:b", ARTIFACTS, { scope: SCOPE }, { message: MESSAGE }, OPTIONS)],
      ["caller sets the secret", () => sdk.zkProve("voting", ARTIFACTS, { scope: SCOPE }, { secret: 1n, message: MESSAGE }, OPTIONS)],
      ["caller sets a random input", () => sdk.zkProve("voting", ARTIFACTS, { scope: SCOPE, r: 1n }, { message: MESSAGE }, OPTIONS)],
      ["input in both public and extra", () => sdk.zkProve("voting", ARTIFACTS, { scope: SCOPE }, { scope: SCOPE, message: MESSAGE }, OPTIONS)],
      ["random declared twice", () => sdk.zkProve("voting", ARTIFACTS, { scope: SCOPE }, { message: MESSAGE }, { ...OPTIONS, random: ["r", "r"] })],
      ["derivation of an unknown input", () => sdk.zkProve("voting", ARTIFACTS, { scope: SCOPE }, { message: MESSAGE }, { ...OPTIONS, derive: { contextSecret: ["secret", "nope"] } })],
      ["derivation of a later derivation", () => sdk.zkProve("voting", ARTIFACTS, { scope: SCOPE }, { message: MESSAGE }, { ...OPTIONS, derive: { a: ["b"], b: ["secret"] } })],
      ["17 terms", () => sdk.zkProve("voting", ARTIFACTS, { scope: SCOPE }, { message: MESSAGE }, { ...OPTIONS, derive: { contextSecret: Array(17).fill("secret") } })],
      ["constant out of the field", () => sdk.zkProve("voting", ARTIFACTS, { scope: SCOPE }, { message: MESSAGE }, { ...OPTIONS, derive: { contextSecret: ["secret", -1n] } })],
      ["non-field input in a derivation", () => sdk.zkProve("voting", ARTIFACTS, { scope: "x" }, { message: MESSAGE }, OPTIONS)],
      ["random not an array", () => sdk.zkProve("voting", ARTIFACTS, { scope: SCOPE }, { message: MESSAGE }, { ...OPTIONS, random: "r" as any })],
      ["derivation of an Object.prototype name", () => sdk.zkProve("voting", ARTIFACTS, { scope: SCOPE }, { message: MESSAGE }, { ...OPTIONS, derive: { contextSecret: ["secret", "toString"] } })],
      ["unknown secret source", () => sdk.zkProve("voting", ARTIFACTS, { scope: SCOPE }, { message: MESSAGE }, { ...OPTIONS, secret: "wallet" as any })],
    ];
    for (const [name, call] of cases) {
      assert((await capture(call)) instanceof CryptoError, `rejects: ${name}`);
    }
    assert(authenticator.calls.length === 0, "no passkey prompt");
    assert(errors.length === cases.length, "reports each to onError");

    const wrongCircuit = await capture(() =>
      sdk.zkProve("voting", ARTIFACTS, { scope: SCOPE }, {}, OPTIONS)
    );
    assert(
      wrongCircuit instanceof CryptoError && /Failed to generate proof/.test(wrongCircuit.message),
      "a missing circuit input fails as CryptoError"
    );
  }
  console.log("");

  console.log("Test 7: proving goes through the worker when Worker exists");
  {
    reset();
    // Runs prove-worker.ts in this thread, with postMessage wired both ways
    const workers: FakeWorker[] = [];
    class FakeWorker {
      onmessage: ((event: { data: unknown }) => void) | null = null;
      onerror: ((event: unknown) => void) | null = null;
      messages: unknown[] = [];
      terminated = false;
      constructor(public url: URL, public options: WorkerOptions) {
        workers.push(this);
        (globalThis as any).postMessage = (data: unknown) =>
          setTimeout(() => !this.terminated && this.onmessage?.({ data }));
        (globalThis as any).onmessage ??= null;
        import("../../src/zk/prove-worker");
      }
      postMessage(data: unknown) {
        this.messages.push(data);
        (globalThis as any).onmessage({ data });
      }
      terminate() {
        this.terminated = true;
      }
    }
    (globalThis as any).Worker = FakeWorker;
    try {
      const result = await new Web3Passkey().zkProve("voting", ARTIFACTS, { scope: SCOPE }, { message: MESSAGE }, OPTIONS);
      const [worker] = workers;
      assert(workers.length === 1, "one worker per proof");
      assert(
        worker.url.href.endsWith("/zk/prove-worker.mjs") && worker.options.type === "module",
        "a module worker at zk/prove-worker.mjs"
      );
      assert(worker.messages.length === 1, "the witness is posted to the worker");
      assert(worker.terminated, "the worker is terminated after the proof");
      assert(await verify(result), "the worker's proof verifies");
    } finally {
      delete (globalThis as any).Worker;
    }
  }
  console.log("");

  console.log("Test 8: a worker that can't start falls back to proving in-thread");
  {
    reset();
    (globalThis as any).Worker = class {
      constructor() {
        throw new TypeError("Invalid URL");
      }
    };
    try {
      const result = await new Web3Passkey().zkProve("voting", ARTIFACTS, { scope: SCOPE }, { message: MESSAGE }, OPTIONS);
      assert(await verify(result), "the in-thread proof verifies");
    } finally {
      delete (globalThis as any).Worker;
    }
  }
  console.log("");

  console.log("==================================================");
  console.log(`${failed === 0 ? "✅" : "❌"} zkProve Tests: ${passed} passed, ${failed} failed`);
  console.log("==================================================\n");
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
