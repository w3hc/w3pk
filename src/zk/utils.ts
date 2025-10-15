/**
 * ZK Utility Functions
 * Helper functions for zero-knowledge proof operations
 */

import { CryptoError } from "../core/errors";

/**
 * Generate a random blinding factor for commitments
 */
export function generateBlinding(): bigint {
  const buffer = new Uint8Array(32);
  crypto.getRandomValues(buffer);
  return bufferToBigInt(buffer);
}

/**
 * Convert buffer to bigint
 */
export function bufferToBigInt(buffer: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < buffer.length; i++) {
    result = (result << 8n) | BigInt(buffer[i]);
  }
  return result;
}

/**
 * Convert bigint to buffer
 */
export function bigIntToBuffer(
  value: bigint,
  byteLength: number = 32
): Uint8Array {
  const buffer = new Uint8Array(byteLength);
  let temp = value;

  for (let i = byteLength - 1; i >= 0; i--) {
    buffer[i] = Number(temp & 0xffn);
    temp = temp >> 8n;
  }

  return buffer;
}

/**
 * Hash a value using SHA-256
 */
export async function sha256Hash(data: string | Uint8Array): Promise<string> {
  try {
    const buffer =
      typeof data === "string" ? new TextEncoder().encode(data) : data;

    const hashBuffer = await crypto.subtle.digest(
      "SHA-256",
      buffer as BufferSource
    );
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  } catch (error) {
    throw new CryptoError("Failed to compute hash", error);
  }
}

/**
 * Build a merkle tree from leaves
 */
export async function buildMerkleTree(leaves: string[]): Promise<{
  root: string;
  tree: string[][];
}> {
  try {
    // @ts-ignore - Optional dependency, may not be installed
    const circomlibjs = await import("circomlibjs");
    const poseidon = await circomlibjs.buildPoseidon();

    if (leaves.length === 0) {
      throw new Error("Cannot build tree from empty leaves");
    }

    const tree: string[][] = [leaves];
    let currentLevel = leaves.map((leaf) => BigInt(leaf));

    while (currentLevel.length > 1) {
      const nextLevel: bigint[] = [];

      for (let i = 0; i < currentLevel.length; i += 2) {
        if (i + 1 < currentLevel.length) {
          const hash = poseidon([currentLevel[i], currentLevel[i + 1]]);
          nextLevel.push(hash);
        } else {
          nextLevel.push(currentLevel[i]);
        }
      }

      tree.push(nextLevel.map((n) => n.toString()));
      currentLevel = nextLevel;
    }

    return {
      root: currentLevel[0].toString(),
      tree,
    };
  } catch (error) {
    if (error instanceof Error && error.message.includes("Cannot resolve module")) {
      throw new CryptoError(
        "ZK merkle tree requires circomlibjs. Install with: npm install circomlibjs\n" +
        "For more info: https://github.com/w3hc/w3pk#zero-knowledge-proofs",
        error
      );
    }
    throw new CryptoError("Failed to build merkle tree", error);
  }
}

/**
 * Generate merkle proof for a leaf
 */
export function generateMerkleProof(
  tree: string[][],
  leafIndex: number
): {
  pathIndices: number[];
  pathElements: string[];
} {
  const pathIndices: number[] = [];
  const pathElements: string[] = [];
  let currentIndex = leafIndex;

  for (let level = 0; level < tree.length - 1; level++) {
    const isRightNode = currentIndex % 2 === 1;
    const siblingIndex = isRightNode ? currentIndex - 1 : currentIndex + 1;

    pathIndices.push(isRightNode ? 1 : 0);

    if (siblingIndex < tree[level].length) {
      pathElements.push(tree[level][siblingIndex]);
    } else {
      pathElements.push(tree[level][currentIndex]);
    }

    currentIndex = Math.floor(currentIndex / 2);
  }

  return { pathIndices, pathElements };
}

/**
 * Validate proof inputs
 */
export function validateProofInputs(inputs: Record<string, any>): void {
  for (const [key, value] of Object.entries(inputs)) {
    if (value === undefined || value === null) {
      throw new CryptoError(`Missing required input: ${key}`);
    }
  }
}

/**
 * Convert hex string to bigint
 */
export function hexToBigInt(hex: string): bigint {
  return BigInt(hex.startsWith("0x") ? hex : `0x${hex}`);
}

/**
 * Convert bigint to hex string
 */
export function bigIntToHex(value: bigint, padToBytes?: number): string {
  let hex = value.toString(16);
  if (padToBytes) {
    hex = hex.padStart(padToBytes * 2, "0");
  }
  return `0x${hex}`;
}

/**
 * Serialize ZK proof for storage or transmission
 */
export function serializeProof(proof: any): string {
  return JSON.stringify(proof);
}

/**
 * Deserialize ZK proof from storage or transmission
 */
export function deserializeProof(serialized: string): any {
  try {
    return JSON.parse(serialized);
  } catch (error) {
    throw new CryptoError("Failed to deserialize proof", error);
  }
}

/**
 * Generate a random nonce for challenges
 */
export function generateNonce(): bigint {
  return generateBlinding();
}

/**
 * Validate Ethereum address format
 */
export function isValidAddress(address: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(address);
}
