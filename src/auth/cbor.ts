/**
 * Strict CBOR decoder (RFC 8949) for the subset WebAuthn attestation objects,
 * authenticator extensions and COSE keys use: integers, byte and text strings,
 * arrays, maps, false, true and null, all of definite length. Tags, floats,
 * other simple values, indefinite lengths, integers outside the safe range and
 * duplicate map keys are refused. Arguments need not use the shortest form.
 */

export type CborValue =
  | boolean
  | null
  | number
  | string
  | Uint8Array
  | CborValue[]
  | Map<number | string, CborValue>;

const MAX_DEPTH = 16;
const utf8 = new TextDecoder("utf-8", { fatal: true });

export class CborError extends Error {}

export function decodeCbor(
  bytes: Uint8Array,
  offset = 0
): { value: CborValue; end: number } {
  const reader = { bytes, pos: offset };
  const value = readItem(reader, 0);
  return { value, end: reader.pos };
}

export function decodeCborExact(bytes: Uint8Array): CborValue {
  const { value, end } = decodeCbor(bytes);
  if (end !== bytes.length) throw new CborError("Trailing bytes after CBOR item");
  return value;
}

interface Reader {
  bytes: Uint8Array;
  pos: number;
}

function take(r: Reader, n: number): Uint8Array {
  if (n > r.bytes.length - r.pos) throw new CborError("Truncated CBOR");
  const out = r.bytes.subarray(r.pos, r.pos + n);
  r.pos += n;
  return out;
}

function readArgument(r: Reader, info: number): number {
  if (info < 24) return info;
  const size = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : info === 27 ? 8 : 0;
  if (size === 0) throw new CborError("Unsupported CBOR length encoding");
  let value = 0;
  for (const byte of take(r, size)) value = value * 256 + byte;
  if (!Number.isSafeInteger(value)) throw new CborError("CBOR integer too large");
  return value;
}

function readItem(r: Reader, depth: number): CborValue {
  if (depth > MAX_DEPTH) throw new CborError("CBOR nested too deeply");
  const [initial] = take(r, 1);
  const major = initial >> 5;
  if (major === 7) return readSimple(initial & 0x1f);
  const arg = readArgument(r, initial & 0x1f);

  switch (major) {
    case 0:
      return arg;
    case 1:
      if (arg === Number.MAX_SAFE_INTEGER) throw new CborError("CBOR integer too large");
      return -1 - arg;
    case 2:
      return take(r, arg).slice();
    case 3:
      try {
        return utf8.decode(take(r, arg));
      } catch (error) {
        if (error instanceof CborError) throw error;
        throw new CborError("Invalid UTF-8 in CBOR text string");
      }
    case 4: {
      const items: CborValue[] = [];
      for (let i = 0; i < arg; i++) items.push(readItem(r, depth + 1));
      return items;
    }
    case 5: {
      const map = new Map<number | string, CborValue>();
      for (let i = 0; i < arg; i++) {
        const key = readItem(r, depth + 1);
        if (typeof key !== "number" && typeof key !== "string") {
          throw new CborError("Unsupported CBOR map key");
        }
        if (map.has(key)) throw new CborError("Duplicate CBOR map key");
        map.set(key, readItem(r, depth + 1));
      }
      return map;
    }
    default:
      throw new CborError("Unsupported CBOR major type");
  }
}

function readSimple(info: number): CborValue {
  if (info === 20) return false;
  if (info === 21) return true;
  if (info === 22) return null;
  throw new CborError("Unsupported CBOR simple value or float");
}
