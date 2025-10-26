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
 * Galois Field (256) operations for Shamir's Secret Sharing
 */
class GF256 {
  // Precomputed logarithm and exponential tables for GF(256)
  private static LOG_TABLE: number[] = [];
  private static EXP_TABLE: number[] = [];

  static {
    // Initialize tables using primitive polynomial x^8 + x^4 + x^3 + x + 1 (0x11b)
    // Generator is 3 (primitive element for this polynomial)

    // Helper function for GF(256) multiplication during initialization
    const gfMul = (a: number, b: number): number => {
      let result = 0;
      for (let i = 0; i < 8; i++) {
        if (b & 1) {
          result ^= a;
        }
        const hiBitSet = a & 0x80;
        a <<= 1;
        if (hiBitSet) {
          a ^= 0x11b; // Polynomial
        }
        b >>= 1;
      }
      return result & 0xFF;
    };

    let x = 1;
    for (let i = 0; i < 255; i++) {
      this.EXP_TABLE[i] = x;
      this.LOG_TABLE[x] = i;
      x = gfMul(x, 3); // Multiply by generator 3
    }
    this.EXP_TABLE[255] = this.EXP_TABLE[0];
  }

  /**
   * Multiply two numbers in GF(256)
   */
  static multiply(a: number, b: number): number {
    if (a === 0 || b === 0) return 0;
    return this.EXP_TABLE[(this.LOG_TABLE[a] + this.LOG_TABLE[b]) % 255];
  }

  /**
   * Divide two numbers in GF(256)
   */
  static divide(a: number, b: number): number {
    if (b === 0) throw new Error('Division by zero in GF(256)');
    if (a === 0) return 0;
    return this.EXP_TABLE[(this.LOG_TABLE[a] - this.LOG_TABLE[b] + 255) % 255];
  }

  /**
   * Add two numbers in GF(256) (XOR)
   */
  static add(a: number, b: number): number {
    return a ^ b;
  }

  /**
   * Evaluate polynomial at x
   */
  static evaluatePolynomial(coefficients: number[], x: number): number {
    let result = 0;
    for (let i = coefficients.length - 1; i >= 0; i--) {
      result = this.add(this.multiply(result, x), coefficients[i]);
    }
    return result;
  }

  /**
   * Lagrange interpolation to recover secret
   */
  static interpolate(shares: { x: number; y: number }[]): number {
    let result = 0;

    for (let i = 0; i < shares.length; i++) {
      let numerator = shares[i].y;
      let denominator = 1;

      for (let j = 0; j < shares.length; j++) {
        if (i !== j) {
          numerator = this.multiply(numerator, shares[j].x);
          denominator = this.multiply(
            denominator,
            this.add(shares[i].x, shares[j].x)
          );
        }
      }

      result = this.add(result, this.divide(numerator, denominator));
    }

    return result;
  }
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
      const y = GF256.evaluatePolynomial(coefficients, x);
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

  const secretLength = shareLength - 1;
  const secret = new Uint8Array(secretLength);

  // For each byte position
  for (let byteIndex = 0; byteIndex < secretLength; byteIndex++) {
    const points: { x: number; y: number }[] = [];

    for (const share of usedShares) {
      points.push({
        x: share[0], // X coordinate
        y: share[byteIndex + 1], // Y coordinate
      });
    }

    // Interpolate to recover secret byte
    secret[byteIndex] = GF256.interpolate(points);
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
