/**
 * The credential public key is decoded from the attested credential data as
 * CBOR and accepted only as an ES256 key on P-256: kty 2, alg -7, crv 1 and
 * 32-byte x and y on the curve.
 */

import { credentialPublicKeyFromAuthData } from "../src/auth/attestation";
import { runTestSuite, assert } from "./test-utils";

const UP = 0x01;
const AT = 0x40;
const ED = 0x80;

function int(n: number): number[] {
  const major = n < 0 ? 0x20 : 0x00;
  const arg = n < 0 ? -1 - n : n;
  if (arg < 24) return [major | arg];
  if (arg < 256) return [major | 24, arg];
  return [major | 25, arg >> 8, arg & 0xff];
}

function bytes(b: ArrayLike<number>): number[] {
  const len = b.length;
  const head = len < 24 ? [0x40 | len] : len < 256 ? [0x58, len] : [0x59, len >> 8, len & 0xff];
  return [...head, ...Array.from(b)];
}

function map(entries: [number, number[]][]): number[] {
  return [0xa0 | entries.length, ...entries.flatMap(([k, v]) => [...int(k), ...v])];
}

function authData(cose: number[], options: { flags?: number; credIdLength?: number; tail?: number[] } = {}) {
  const credId = new Uint8Array(16).fill(7);
  const credIdLength = options.credIdLength ?? credId.length;
  return new Uint8Array([
    ...new Uint8Array(32),
    options.flags ?? UP | AT,
    0, 0, 0, 0,
    ...new Uint8Array(16),
    credIdLength >> 8, credIdLength & 0xff,
    ...credId,
    ...cose,
    ...(options.tail ?? []),
  ]);
}

function es256(x: ArrayLike<number>, y: ArrayLike<number>, overrides: { kty?: number; alg?: number; crv?: number } = {}) {
  return map([
    [1, int(overrides.kty ?? 2)],
    [3, int(overrides.alg ?? -7)],
    [-1, int(overrides.crv ?? 1)],
    [-2, bytes(x)],
    [-3, bytes(y)],
  ]);
}

let x: Uint8Array;
let y: Uint8Array;
let spki: Uint8Array;

async function setup() {
  const { publicKey } = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", publicKey));
  x = raw.slice(1, 33);
  y = raw.slice(33, 65);
  spki = new Uint8Array(await crypto.subtle.exportKey("spki", publicKey));
}

function refused(data: () => Uint8Array, what: string, message?: string) {
  return async () => {
    let error: Error | undefined;
    try {
      await credentialPublicKeyFromAuthData(data());
    } catch (e) {
      error = e as Error;
    }
    assert(error !== undefined, `${what} should be refused`);
    if (message) assert(error.message === message, `${what}: expected "${message}", got "${error.message}"`);
  };
}

setup().then(() =>
  runTestSuite("Attestation COSE Key Tests", [
    {
      name: "valid ES256 key is decoded to its SPKI",
      fn: async () => {
        const out = new Uint8Array(await credentialPublicKeyFromAuthData(authData(es256(x, y))));
        assert(out.join() === spki.join(), "SPKI should match the authenticator's key");
      },
    },
    {
      name: "map keys in another order are accepted",
      fn: async () => {
        const cose = map([[-3, bytes(y)], [-2, bytes(x)], [-1, int(1)], [3, int(-7)], [1, int(2)]]);
        const out = new Uint8Array(await credentialPublicKeyFromAuthData(authData(cose)));
        assert(out.join() === spki.join(), "SPKI should match the authenticator's key");
      },
    },
    {
      name: "extensions after the key are accepted when ED is set",
      fn: async () => {
        const extensions = [0xa1, 0x6b, ...new TextEncoder().encode("credProtect"), 0x02];
        const out = new Uint8Array(
          await credentialPublicKeyFromAuthData(authData(es256(x, y), { flags: UP | AT | ED, tail: extensions }))
        );
        assert(out.join() === spki.join(), "SPKI should match the authenticator's key");
      },
    },
    {
      name: "RSA modulus containing the old scan pattern is refused",
      fn: async () => {
        const n = new Uint8Array(256).fill(0xab);
        n.set([0x21, 0x58, 0x20, ...x, 0x22, 0x58, 0x20, ...y], 40);
        const rs256 = map([[1, int(3)], [3, int(-257)], [-1, bytes(n)], [-2, bytes([1, 0, 1])]]);
        await refused(() => authData(rs256), "an RS256 key", "Credential public key is not EC2")();
      },
    },
    {
      name: "OKP Ed25519 key is refused",
      fn: refused(
        () => authData(map([[1, int(1)], [3, int(-8)], [-1, int(6)], [-2, bytes(x)]])),
        "an Ed25519 key",
        "Credential public key is not EC2"
      ),
    },
    {
      name: "EC2 key with ES384 alg is refused",
      fn: refused(() => authData(es256(x, y, { alg: -35 })), "an ES384 alg", "Credential public key is not ES256"),
    },
    {
      name: "EC2 key on P-384 is refused",
      fn: refused(() => authData(es256(x, y, { crv: 2 })), "a P-384 curve", "Credential public key is not on P-256"),
    },
    {
      name: "short x is refused",
      fn: refused(() => authData(es256(x.slice(1), y)), "a 31-byte x", "Credential public key has invalid coordinates"),
    },
    {
      name: "long y is refused",
      fn: refused(() => authData(es256(x, [0, ...y])), "a 33-byte y", "Credential public key has invalid coordinates"),
    },
    {
      name: "missing y is refused",
      fn: refused(
        () => authData(map([[1, int(2)], [3, int(-7)], [-1, int(1)], [-2, bytes(x)]])),
        "a key without y",
        "Credential public key has invalid coordinates"
      ),
    },
    {
      name: "point off the curve is refused",
      fn: refused(
        () => authData(es256(new Uint8Array(32).fill(1), new Uint8Array(32).fill(1))),
        "a point off the curve",
        "Credential public key is not a point on P-256"
      ),
    },
    {
      name: "duplicate kty is refused",
      fn: refused(() => authData([0xa6, 0x01, 0x02, ...es256(x, y).slice(1)]), "a duplicate kty"),
    },
    {
      name: "trailing bytes without ED are refused",
      fn: refused(() => authData(es256(x, y), { tail: [0x00] }), "trailing bytes", "Trailing bytes after attested credential data"),
    },
    {
      name: "truncated key is refused",
      fn: refused(() => authData(es256(x, y).slice(0, -1)), "a truncated key"),
    },
    {
      name: "missing AT flag is refused",
      fn: refused(() => authData(es256(x, y), { flags: UP }), "authData without AT", "Attested credential data missing"),
    },
    {
      name: "credential ID length past the end is refused",
      fn: refused(() => authData([], { credIdLength: 1000 }), "a credential ID past the end", "Invalid credential ID length"),
    },
  ])
);
