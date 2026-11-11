/**
 * Mocked authenticator for PRF tests: one P-256 key and one PRF secret per
 * credential. Assertions are signed over authenticatorData || SHA-256(
 * clientDataJSON) as WebAuthn L3 §6.3.3 describes, and the PRF is
 * HMAC-SHA256(credential secret, SHA-256("WebAuthn PRF" || 0x00 || input)),
 * as §10.1.4 describes.
 */

import { CredentialStorage } from "../src/auth/storage";
import { arrayBufferToBase64Url } from "../src/utils/base64";
import { macPublicKey, PRF_INPUT } from "../src/wallet/crypto";

export const UP = 0x01;
export const UV = 0x04;

export async function prf(secret: Uint8Array, input: BufferSource): Promise<ArrayBuffer> {
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

export function rawToDer(raw: Uint8Array): Uint8Array {
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

function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]) as Promise<CryptoKeyPair>;
}

export class PrfAuthenticator {
  /** Credential used when the request has no allowCredentials */
  selected: string;
  prf = true;
  flags = UP | UV;
  /** Sign with a key other than the credential's */
  badSignature = false;
  reject: Error | null = null;
  calls: PublicKeyCredentialRequestOptions[] = [];

  private readonly secrets: Map<string, Uint8Array>;
  private readonly keys: Promise<Map<string, CryptoKeyPair>>;
  private readonly otherKey = generateKeyPair();
  private signCount = 0;

  constructor(private readonly rpId: string, private readonly ids: string[]) {
    this.selected = ids[0];
    this.secrets = new Map(ids.map((id) => [id, crypto.getRandomValues(new Uint8Array(32))]));
    this.keys = Promise.all(ids.map(async (id) => [id, await generateKeyPair()] as const)).then(
      (entries) => new Map(entries)
    );
  }

  reset(): void {
    this.selected = this.ids[0];
    this.prf = true;
    this.flags = UP | UV;
    this.badSignature = false;
    this.reject = null;
    this.calls = [];
  }

  secret(id: string): Uint8Array {
    return this.secrets.get(id)!;
  }

  async publicKey(id: string): Promise<string> {
    const { publicKey } = (await this.keys).get(id)!;
    return arrayBufferToBase64Url(await crypto.subtle.exportKey("spki", publicKey));
  }

  /** Save every credential's metadata, with its public key MAC, as register() does */
  async store(storage: Storage, username: string, ethereumAddress: string): Promise<void> {
    const credentials = new CredentialStorage(storage);
    const now = new Date().toISOString();
    for (const [i, id] of this.ids.entries()) {
      const publicKey = await this.publicKey(id);
      await credentials.saveCredential({
        id,
        publicKey,
        username: i === 0 ? username : `${username}${i}`,
        ethereumAddress,
        createdAt: now,
        lastUsed: now,
        publicKeyMac: await macPublicKey(await prf(this.secret(id), PRF_INPUT), id, publicKey),
      });
    }
  }

  install(): void {
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {
        userAgent: "node",
        credentials: {
          get: ({ publicKey }: { publicKey: PublicKeyCredentialRequestOptions }) => this.get(publicKey),
        },
      },
    });
  }

  private async get(options: PublicKeyCredentialRequestOptions) {
    this.calls.push(options);
    if (this.reject) throw this.reject;

    const allowed = (options.allowCredentials ?? []).map((c) =>
      arrayBufferToBase64Url(c.id as ArrayBuffer)
    );
    const id = allowed.length > 0 ? allowed[0] : this.selected;

    const evaluate = (options.extensions as any)?.prf?.eval;
    const results: { first?: ArrayBuffer; second?: ArrayBuffer } = {};
    if (this.prf && evaluate?.first) {
      results.first = await prf(this.secret(id), evaluate.first);
      if (evaluate.second) results.second = await prf(this.secret(id), evaluate.second);
    }

    this.signCount++;
    const authenticatorData = new Uint8Array(37);
    authenticatorData.set(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(this.rpId))),
      0
    );
    authenticatorData[32] = this.flags;
    new DataView(authenticatorData.buffer).setUint32(33, this.signCount);

    const clientDataJSON = new TextEncoder().encode(
      JSON.stringify({
        type: "webauthn.get",
        challenge: arrayBufferToBase64Url(options.challenge as ArrayBuffer),
        origin: (globalThis as any).window.location.origin,
      })
    );
    const clientDataHash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataJSON));
    const { privateKey } = this.badSignature ? await this.otherKey : (await this.keys).get(id)!;
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        privateKey,
        new Uint8Array([...authenticatorData, ...clientDataHash])
      )
    );

    return {
      id,
      rawId: new Uint8Array(16).buffer,
      type: "public-key",
      response: {
        authenticatorData: authenticatorData.buffer,
        clientDataJSON: clientDataJSON.buffer,
        signature: rawToDer(signature).buffer,
      },
      getClientExtensionResults: () => (results.first ? { prf: { results } } : {}),
    };
  }
}
