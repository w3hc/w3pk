/**
 * Cryptographic utility functions for WebAuthn and P-256 signatures
 */

/**
 * Extracts r and s values from a DER-encoded ECDSA signature
 * Applies low-s normalization for Ethereum compatibility
 *
 * @param derSignature - DER-encoded signature from WebAuthn
 * @returns Object containing hex-encoded r and s values with 0x prefix
 * @throws Error if the signature format is invalid
 */
export function extractRS(derSignature: Uint8Array): { r: string; s: string } {
  let offset = 0;

  // Check sequence tag (0x30)
  if (derSignature[offset++] !== 0x30) {
    throw new Error('Invalid DER signature: missing sequence tag');
  }

  // Skip sequence length
  offset++;

  // Read r integer
  if (derSignature[offset++] !== 0x02) {
    throw new Error('Invalid DER signature: missing r integer tag');
  }

  let rLength = derSignature[offset++];
  // Handle high byte padding (if r has high bit set, DER adds 0x00 prefix)
  if (rLength > 32) {
    offset++;
    rLength--;
  }
  const rBytes = derSignature.slice(offset, offset + rLength);
  offset += rLength;

  // Read s integer
  if (derSignature[offset++] !== 0x02) {
    throw new Error('Invalid DER signature: missing s integer tag');
  }

  let sLength = derSignature[offset++];
  // Handle high byte padding
  if (sLength > 32) {
    offset++;
    sLength--;
  }
  const sBytes = derSignature.slice(offset, offset + sLength);

  // Pad to 32 bytes if needed
  const rPadded = new Uint8Array(32);
  const sPadded = new Uint8Array(32);
  rPadded.set(rBytes, 32 - rBytes.length);
  sPadded.set(sBytes, 32 - sBytes.length);

  // P-256 curve order (for low-s normalization)
  const n = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');
  let sBigInt = BigInt('0x' + Buffer.from(sPadded).toString('hex'));

  // Low-s normalization: if s > n/2, then s = n - s
  // This is required for Ethereum signature verification
  if (sBigInt > n / 2n) {
    sBigInt = n - sBigInt;
  }

  const r = '0x' + Buffer.from(rPadded).toString('hex');
  const s = '0x' + sBigInt.toString(16).padStart(64, '0');

  return { r, s };
}
