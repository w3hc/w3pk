/**
 * Cryptographic utility functions for WebAuthn and P-256 signatures
 */

import { bytesToHex } from "@noble/hashes/utils.js";

/**
 * Parse a DER-encoded ECDSA P-256 signature (SEQUENCE of two INTEGERs)
 * into r and s, each left-padded to 32 bytes
 *
 * @throws Error if the encoding is malformed or a value is longer than 32 bytes
 */
export function parseDerSignature(der: Uint8Array): { r: Uint8Array; s: Uint8Array } {
  if (der.length < 8 || der[0] !== 0x30) {
    throw new Error('Invalid DER signature: missing sequence tag');
  }
  if (der[1] !== der.length - 2) {
    throw new Error('Invalid DER signature: sequence length mismatch');
  }

  let offset = 2;
  const readInteger = (name: string): Uint8Array => {
    if (offset + 2 > der.length || der[offset] !== 0x02) {
      throw new Error(`Invalid DER signature: missing ${name} integer tag`);
    }
    const length = der[offset + 1];
    offset += 2;
    if (length === 0 || length > 33 || offset + length > der.length) {
      throw new Error(`Invalid DER signature: bad ${name} length`);
    }
    let value = der.subarray(offset, offset + length);
    offset += length;
    if (length === 33) {
      if (value[0] !== 0x00) {
        throw new Error(`Invalid DER signature: ${name} longer than 32 bytes`);
      }
      value = value.subarray(1);
    }
    const padded = new Uint8Array(32);
    padded.set(value, 32 - value.length);
    return padded;
  };

  const r = readInteger('r');
  const s = readInteger('s');
  if (offset !== der.length) {
    throw new Error('Invalid DER signature: trailing bytes');
  }
  return { r, s };
}

/**
 * Extracts r and s values from a DER-encoded ECDSA signature
 * Applies low-s normalization for Ethereum compatibility
 *
 * @param derSignature - DER-encoded signature from WebAuthn
 * @returns Object containing hex-encoded r and s values with 0x prefix
 * @throws Error if the signature format is invalid
 */
export function extractRS(derSignature: Uint8Array): { r: string; s: string } {
  const { r, s } = parseDerSignature(derSignature);

  // P-256 curve order (for low-s normalization)
  const n = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');
  let sBigInt = BigInt('0x' + bytesToHex(s));

  // Low-s normalization: if s > n/2, then s = n - s
  // This is required for Ethereum signature verification
  if (sBigInt > n / 2n) {
    sBigInt = n - sBigInt;
  }

  return {
    r: '0x' + bytesToHex(r),
    s: '0x' + sBigInt.toString(16).padStart(64, '0'),
  };
}
