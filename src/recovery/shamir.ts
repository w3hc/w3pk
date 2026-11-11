/**
 * Shamir's Secret Sharing Implementation
 * Browser-compatible implementation without external dependencies
 *
 * Based on Shamir's Secret Sharing algorithm over GF(256)
 */

/**
 * Generate random byte
 */
function randomByte(): number {
  const array = new Uint8Array(1);
  crypto.getRandomValues(array);
  return array[0];
}

/**
 * GF(2^8) with the AES polynomial x^8 + x^4 + x^3 + x + 1 (FIPS-197 §4.2),
 * in constant time: no branch or table lookup depends on the operands
 * (shift-and-add with masks, as HashiCorp Vault's `shamir` package does).
 */
export function gfMul(a: number, b: number): number {
  let r = 0;
  for (let i = 7; i >= 0; i--) {
    r = (-((b >> i) & 1) & a) ^ (-(r >> 7) & 0x1b) ^ ((r << 1) & 0xff);
  }
  return r;
}

/** a^254, the inverse of a (FIPS-197 §4.4), and 0 for 0 */
export function gfInv(a: number): number {
  let r = a;
  for (let i = 0; i < 6; i++) {
    r = gfMul(gfMul(r, r), a);
  }
  return gfMul(r, r);
}

function evaluatePolynomial(coefficients: number[], x: number): number {
  let result = 0;
  for (let i = coefficients.length - 1; i >= 0; i--) {
    result = gfMul(result, x) ^ coefficients[i];
  }
  return result;
}

/**
 * Lagrange basis polynomials at 0 for the x-coordinates `xs` (distinct and
 * non-zero): the secret is the XOR of gfMul(basis[i], y[i]).
 */
function lagrangeAtZero(xs: number[]): number[] {
  return xs.map((xi, i) => {
    let numerator = 1;
    let denominator = 1;
    xs.forEach((xj, j) => {
      if (i !== j) {
        numerator = gfMul(numerator, xj);
        denominator = gfMul(denominator, xi ^ xj);
      }
    });
    return gfMul(numerator, gfInv(denominator));
  });
}

/**
 * Split secret into N shares (requires M to reconstruct)
 */
export function splitSecret(
  secret: Uint8Array,
  threshold: number,
  totalShares: number
): Uint8Array[] {
  if (threshold > totalShares) {
    throw new Error('Threshold cannot be greater than total shares');
  }

  if (threshold < 2) {
    throw new Error('Threshold must be at least 2');
  }

  if (totalShares > 255) {
    throw new Error('Cannot create more than 255 shares');
  }

  const shares: Uint8Array[] = [];

  // Initialize shares
  for (let i = 0; i < totalShares; i++) {
    shares[i] = new Uint8Array(secret.length + 1);
    shares[i][0] = i + 1; // X coordinate (1-indexed)
  }

  // For each byte of the secret
  for (let byteIndex = 0; byteIndex < secret.length; byteIndex++) {
    const secretByte = secret[byteIndex];

    // Generate random polynomial coefficients
    const coefficients = [secretByte];
    for (let i = 1; i < threshold; i++) {
      coefficients.push(randomByte());
    }

    // Evaluate polynomial for each share
    for (let shareIndex = 0; shareIndex < totalShares; shareIndex++) {
      const x = shareIndex + 1;
      const y = evaluatePolynomial(coefficients, x);
      shares[shareIndex][byteIndex + 1] = y;
    }
  }

  return shares;
}

/**
 * Combine shares to recover secret
 */
export function combineShares(
  shares: Uint8Array[],
  threshold: number
): Uint8Array {
  if (shares.length < threshold) {
    throw new Error(
      `Need at least ${threshold} shares to recover secret, got ${shares.length}`
    );
  }

  // Use only first 'threshold' shares
  const usedShares = shares.slice(0, threshold);

  // Verify all shares have same length
  const shareLength = usedShares[0].length;
  for (const share of usedShares) {
    if (share.length !== shareLength) {
      throw new Error('All shares must have the same length');
    }
  }

  const basis = lagrangeAtZero(usedShares.map((share) => share[0]));
  const secret = new Uint8Array(shareLength - 1);
  for (let byteIndex = 0; byteIndex < secret.length; byteIndex++) {
    let byte = 0;
    usedShares.forEach((share, i) => {
      byte ^= gfMul(basis[i], share[byteIndex + 1]);
    });
    secret[byteIndex] = byte;
  }

  return secret;
}

/**
 * Helper: Convert string to Uint8Array
 */
export function stringToBytes(str: string): Uint8Array {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

/**
 * Helper: Convert Uint8Array to string
 */
export function bytesToString(bytes: Uint8Array): string {
  const decoder = new TextDecoder();
  return decoder.decode(bytes);
}

/**
 * Helper: Convert bytes to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Helper: Convert hex string to bytes
 */
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}
