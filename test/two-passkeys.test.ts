/**
 * Two passkeys for one wallet (#267): registering a second passkey with
 * registerWithBackupFile() keeps the first one's wallet record, and both
 * log in
 *
 * Mocks navigator.credentials with an authenticator holding several P-256
 * passkeys that sign real assertions, each with a PRF computed as the spec
 * describes, HMAC-SHA256(credential secret, SHA-256("WebAuthn PRF" || 0x00 || input)).
 *
 * NOTE: the mnemonic is the standard BIP39 test vector, not a real secret
 */

import { Wallet } from "ethers";
import { Web3Passkey } from "../src/index";
import { BackupFileManager } from "../src/backup/backup-file";
import { arrayBufferToBase64Url } from "../src/utils/base64";

console.log("\n==================================================");
console.log("🔑 Two Passkeys for One Wallet Test");
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
const PASSWORD = "TestStrongPass123!NotReal";
const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ADDRESS = Wallet.fromPhrase(MNEMONIC).address;

const UP = 0x01;
const UV = 0x04;
const AT = 0x40;

const localStorage = new MemoryStorage();
(globalThis as any).localStorage = localStorage;
(globalThis as any).window = {
  location: { hostname: RP_ID, origin: `http://${RP_ID}` },
  localStorage,
};

interface Passkey {
  id: string;
  username: string;
  keyPair: CryptoKeyPair;
  secret: Uint8Array;
  signCount: number;
}

const authenticator = {
  passkeys: [] as Passkey[],
  selected: null as Passkey | null,
  requests: [] as PublicKeyCredentialRequestOptions[],
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

async function prf(secret: Uint8Array, input: BufferSource): Promise<ArrayBuffer> {
  const label = new TextEncoder().encode("WebAuthn PRF");
  const bytes = new Uint8Array(
    ArrayBuffer.isView(input)
      ? input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength)
      : input
  );
  const salt = await crypto.subtle.digest("SHA-256", new Uint8Array([...label, 0, ...bytes]));
  const key = await crypto.subtle.importKey(
    "raw",
    secret,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return crypto.subtle.sign("HMAC", key, salt);
}

async function prfResults(passkey: Passkey, extensions: any) {
  const inputs = extensions?.prf?.eval;
  if (!inputs?.first) return {};
  const first = await prf(passkey.secret, inputs.first);
  const second = inputs.second ? await prf(passkey.secret, inputs.second) : undefined;
  return { prf: { results: second ? { first, second } : { first } } };
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
  const authDataKey = [0x68, ...new TextEncoder().encode("authData")];
  return new Uint8Array([
    0xa3,
    ...authDataKey,
    0x59, authData.length >> 8, authData.length & 0xff,
    ...authData,
  ]).buffer;
}

Object.defineProperty(globalThis, "navigator", {
  configurable: true,
  value: {
    userAgent: "node",
    credentials: {
      create: async ({ publicKey }: { publicKey: PublicKeyCredentialCreationOptions }) => {
        const passkey: Passkey = {
          id: arrayBufferToBase64Url(crypto.getRandomValues(new Uint8Array(16)).buffer),
          username: publicKey.user.name,
          keyPair: await crypto.subtle.generateKey(
            { name: "ECDSA", namedCurve: "P-256" },
            true,
            ["sign", "verify"]
          ),
          secret: crypto.getRandomValues(new Uint8Array(32)),
          signCount: 0,
        };
        authenticator.passkeys.push(passkey);
        const raw = new Uint8Array(await crypto.subtle.exportKey("raw", passkey.keyPair.publicKey));
        const extensions = await prfResults(passkey, publicKey.extensions);
        return {
          id: passkey.id,
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
          getClientExtensionResults: () => extensions,
        };
      },
      get: async ({ publicKey }: { publicKey: PublicKeyCredentialRequestOptions }) => {
        authenticator.requests.push(publicKey);
        const passkey = authenticator.selected;
        if (!passkey) throw Object.assign(new Error("Cancelled"), { name: "NotAllowedError" });

        passkey.signCount++;
        const authenticatorData = new Uint8Array(37);
        authenticatorData.set(await rpIdHash(), 0);
        authenticatorData[32] = UP | UV;
        new DataView(authenticatorData.buffer).setUint32(33, passkey.signCount);

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
            passkey.keyPair.privateKey,
            new Uint8Array([...authenticatorData, ...clientDataHash])
          )
        );
        const extensions = await prfResults(passkey, publicKey.extensions);

        return {
          id: passkey.id,
          rawId: new Uint8Array(16).buffer,
          type: "public-key",
          response: {
            authenticatorData: authenticatorData.buffer,
            clientDataJSON: clientDataJSON.buffer,
            signature: rawToDer(signature).buffer,
            userHandle: new TextEncoder().encode(passkey.username).buffer,
          },
          getClientExtensionResults: () => extensions,
        };
      },
    },
  },
});

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

  const { json: backup } = await new BackupFileManager().createPasswordBackup(MNEMONIC, PASSWORD);

  async function registerTwoPasskeys(config: ConstructorParameters<typeof Web3Passkey>[0]) {
    localStorage.clear();
    authenticator.passkeys = [];

    const first = new Web3Passkey(config);
    (first as any).currentWallet = { address: ADDRESS, mnemonic: MNEMONIC };
    await first.register({ username: "alice" });
    await first.logout();

    const second = new Web3Passkey(config);
    await second.registerWithBackupFile(backup, PASSWORD, "bob");
    await second.logout();

    return authenticator.passkeys;
  }

  async function logsIn(
    passkey: Passkey,
    config: ConstructorParameters<typeof Web3Passkey>[0],
    label: string
  ) {
    authenticator.selected = passkey;
    const sdk = new Web3Passkey(config);
    const error = await sdk.login().then(() => undefined, (e) => e);
    assert(error === undefined && sdk.user?.ethereumAddress === ADDRESS, `${label} logs in to the wallet`);
    assert(sdk.user?.credentialId === passkey.id, `${label} is the logged-in passkey`);
    const opened = await sdk.deriveWallet().then((w) => w.address !== undefined, () => false);
    assert(opened, `${label} opens the wallet`);
  }

  for (const [label, config] of [
    ["without persistent sessions", {}],
    ["with persistent sessions", { persistentSession: { enabled: true, requireReauth: true } }],
  ] as const) {
    console.log(`Test: register a second passkey from a backup, ${label}`);
    {
      const [a, b] = await registerTwoPasskeys(config);
      assert(a !== undefined && b !== undefined && a.id !== b.id, "two passkeys are registered");
      assert(
        localStorage.getItem(`w3pk_wallet_${a.id}`) !== null &&
          localStorage.getItem(`w3pk_wallet_${b.id}`) !== null,
        "each passkey has its own wallet record"
      );
      await logsIn(a, config, "passkey A");
      await logsIn(b, config, "passkey B");
      await logsIn(a, config, "passkey A again");
      if ("persistentSession" in config) {
        assert(
          localStorage.getItem(`w3pk_session_${a.id}`) !== null &&
            localStorage.getItem(`w3pk_session_${b.id}`) !== null,
          "each passkey keeps its own persistent session"
        );
      }
    }
    console.log("");
  }

  console.log("Test: re-authentication offers only the logged-in passkey");
  {
    const [a] = await registerTwoPasskeys({});
    authenticator.selected = a;
    const sdk = new Web3Passkey();
    await sdk.login();
    authenticator.requests = [];
    const mnemonic = await (sdk as any).getMnemonicFromSession(true);
    const allowed = authenticator.requests[0]?.allowCredentials ?? [];
    assert(mnemonic === MNEMONIC, "the wallet opens");
    assert(
      allowed.length === 1 &&
        arrayBufferToBase64Url(allowed[0].id as ArrayBuffer) === a.id,
      "the prompt offers passkey A only"
    );
  }
  console.log("");

  console.log("==================================================");
  console.log(`✅ Two Passkeys Tests: ${passed} passed, ${failed} failed`);
  console.log("==================================================\n");

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
