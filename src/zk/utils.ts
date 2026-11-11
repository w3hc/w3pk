/**
 * ZK Utility Functions
 * Helper functions for zero-knowledge proof operations
 */

import { CryptoError } from "../core/errors";
import type { NFTOwnershipProofInput } from "./types";

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
 * Stretch a key using PBKDF2
 * Use case: Password hashing, deterministic key derivation
 *
 * @param input - The input string to stretch (e.g., password)
 * @param salt - Salt value to prevent rainbow table attacks
 * @param iterations - Number of iterations (default: 10000)
 * @param keyLength - Output key length in bytes (default: 32)
 * @returns Hex-encoded stretched key
 */
export async function stretchKey(
  input: string,
  salt: string,
  iterations: number = 10000,
  keyLength: number = 32
): Promise<string> {
  try {
    const encoder = new TextEncoder();
    const inputBuffer = encoder.encode(input);
    const saltBuffer = encoder.encode(salt);

    // Import the password as a key for PBKDF2
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      inputBuffer,
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    // Derive bits using PBKDF2
    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: saltBuffer,
        iterations: iterations,
        hash: "SHA-256",
      },
      keyMaterial,
      keyLength * 8 // Convert bytes to bits
    );

    // Convert to hex string
    const hashArray = Array.from(new Uint8Array(derivedBits));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  } catch (error) {
    throw new CryptoError("Failed to stretch key", error);
  }
}

/**
 * Hash data with salt using SHA-256
 * Use case: Creating deterministic identifiers
 *
 * @param data - The data to hash
 * @param salt - Salt value for additional entropy
 * @returns Hex-encoded hash
 */
export async function hashWithSalt(
  data: string,
  salt: string
): Promise<string> {
  try {
    const combined = data + salt;
    return await sha256Hash(combined);
  } catch (error) {
    throw new CryptoError("Failed to hash with salt", error);
  }
}

/**
 * Hash data multiple times (key stretching)
 * Use case: Making brute-force attacks impractical
 *
 * @param data - The data to hash
 * @param salt - Salt value to prevent rainbow table attacks
 * @param iterations - Number of hash iterations
 * @returns Hex-encoded hash after multiple iterations
 */
export async function iterativeHash(
  data: string,
  salt: string,
  iterations: number
): Promise<string> {
  try {
    if (iterations < 1) {
      throw new Error("Iterations must be at least 1");
    }

    // Initial hash with salt
    let hash = await hashWithSalt(data, salt);

    // Iteratively hash the result
    for (let i = 1; i < iterations; i++) {
      hash = await sha256Hash(hash);
    }

    return hash;
  } catch (error) {
    throw new CryptoError("Failed to perform iterative hash", error);
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
          nextLevel.push(poseidon.F.toObject(poseidon([currentLevel[i], currentLevel[i + 1]])));
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

/** Depth of the NFT holders tree, fixed by nft.circom */
export const NFT_TREE_DEPTH = 20;

const SNARK_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const BALANCE_LIMIT = 1n << 64n;

export interface NFTHolder {
  /** The holder's identity commitment, from `getNFTHolderCommitment()` */
  commitment: string | bigint;
  /** The holder's balance at the snapshot, below 2^64 */
  balance: bigint;
}

function toFieldElement(value: string | bigint, name: string): bigint {
  let field: bigint;
  try {
    field = BigInt(value);
  } catch {
    throw new CryptoError(`${name} is not a field element`);
  }
  if (field < 0n || field >= SNARK_FIELD) {
    throw new CryptoError(`${name} is not in the BN254 scalar field`);
  }
  return field;
}

function assertBalance(value: bigint, name: string): void {
  if (typeof value !== "bigint" || value < 0n || value >= BALANCE_LIMIT) {
    throw new CryptoError(`${name} must be a bigint in [0, 2^64)`);
  }
}

async function loadPoseidon(): Promise<typeof import("poseidon-lite")> {
  try {
    return await import("poseidon-lite");
  } catch (error) {
    throw new CryptoError(
      "NFT holder trees require poseidon-lite. Install with: pnpm add poseidon-lite",
      error
    );
  }
}

/**
 * Build the NFT holders tree `nft.circom` proves against: leaf i is
 * Poseidon(commitment, contract, balance) of holder i, empty leaves are 0,
 * and the tree has `NFT_TREE_DEPTH` levels. `tree[d]` holds the non-empty
 * nodes of level d; `tree[NFT_TREE_DEPTH]` is `[root]`.
 *
 * Check each holder's commitment registration and balance before adding it:
 * the tree is what the proof trusts.
 */
export async function buildNFTHoldersMerkleTree(
  holders: NFTHolder[],
  contractAddress: string
): Promise<{
  root: string;
  tree: string[][];
  holderLeaves: string[];
}> {
  if (!isValidAddress(contractAddress)) {
    throw new CryptoError(`Invalid contract address: ${contractAddress}`);
  }
  if (holders.length === 0) {
    throw new CryptoError("Cannot build NFT holders tree from empty holder list");
  }
  if (holders.length > 2 ** NFT_TREE_DEPTH) {
    throw new CryptoError(`NFT holders tree holds at most 2^${NFT_TREE_DEPTH} holders`);
  }

  const contract = BigInt(contractAddress);
  const seen = new Set<bigint>();
  const commitments = holders.map(({ commitment, balance }, i) => {
    const field = toFieldElement(commitment, `Holder ${i} commitment`);
    if (seen.has(field)) {
      throw new CryptoError(`Holder ${i} commitment is in the list twice`);
    }
    seen.add(field);
    assertBalance(balance, `Holder ${i} balance`);
    return field;
  });

  const { poseidon2, poseidon3 } = await loadPoseidon();
  let level = commitments.map((c, i) => poseidon3([c, contract, holders[i].balance]));
  const tree: string[][] = [level.map(String)];
  let zero = 0n;
  for (let d = 0; d < NFT_TREE_DEPTH; d++) {
    const next: bigint[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(poseidon2([level[i], i + 1 < level.length ? level[i + 1] : zero]));
    }
    tree.push(next.map(String));
    level = next;
    zero = poseidon2([zero, zero]);
  }

  return { root: tree[NFT_TREE_DEPTH][0], tree, holderLeaves: tree[0] };
}

/**
 * Prepare `proveNFTOwnership()`'s input for the holder with
 * `holderCommitment`: its balance and its `NFT_TREE_DEPTH`-level path in
 * the tree of `holders`
 */
export async function generateNFTOwnershipProofInputs(
  holderCommitment: string | bigint,
  contractAddress: string,
  holders: NFTHolder[],
  scope: bigint | string,
  minBalance: bigint = 1n
): Promise<{
  nftProofInput: NFTOwnershipProofInput;
  holderLeaves: string[];
}> {
  const commitment = toFieldElement(holderCommitment, "Holder commitment");
  const holderIndex = holders.findIndex((holder) => {
    try {
      return BigInt(holder.commitment) === commitment;
    } catch {
      return false;
    }
  });
  if (holderIndex === -1) {
    throw new CryptoError(
      `Commitment ${commitment} not found in holders list for contract ${contractAddress}`
    );
  }
  const { balance } = holders[holderIndex];
  assertBalance(minBalance, "Minimum balance");
  if (balance < minBalance) {
    throw new CryptoError(`Holder balance ${balance} is below the minimum ${minBalance}`);
  }

  const { root, tree, holderLeaves } = await buildNFTHoldersMerkleTree(holders, contractAddress);
  const { poseidon2 } = await loadPoseidon();

  const pathIndices: number[] = [];
  const pathElements: string[] = [];
  let index = holderIndex;
  let zero = 0n;
  for (let d = 0; d < NFT_TREE_DEPTH; d++) {
    pathIndices.push(index & 1);
    pathElements.push(tree[d][index ^ 1] ?? zero.toString());
    index >>= 1;
    zero = poseidon2([zero, zero]);
  }

  return {
    nftProofInput: {
      balance,
      pathIndices,
      pathElements,
      holdersRoot: root,
      contractAddress,
      minBalance,
      scope,
    },
    holderLeaves,
  };
}

/**
 * Validate NFT ownership proof inputs
 */
export function validateNFTOwnershipProofInputs(inputs: NFTOwnershipProofInput): void {
  if (!isValidAddress(inputs.contractAddress)) {
    throw new CryptoError(`Invalid contract address: ${inputs.contractAddress}`);
  }

  if (
    inputs.pathIndices.length !== NFT_TREE_DEPTH ||
    inputs.pathElements.length !== NFT_TREE_DEPTH
  ) {
    throw new CryptoError(
      `Merkle path must have ${NFT_TREE_DEPTH} levels, got ${inputs.pathIndices.length} indices and ${inputs.pathElements.length} elements`
    );
  }

  if (inputs.pathIndices.some((index) => index !== 0 && index !== 1)) {
    throw new CryptoError("Path indices must be 0 or 1");
  }

  inputs.pathElements.forEach((element, i) => toFieldElement(element, `Path element ${i}`));
  toFieldElement(inputs.holdersRoot, "Holders root");
  toFieldElement(inputs.scope, "Scope");

  const minBalance = inputs.minBalance ?? 1n;
  assertBalance(inputs.balance, "Balance");
  assertBalance(minBalance, "Minimum balance");
  if (minBalance < 1n) {
    throw new CryptoError("Minimum balance must be at least 1");
  }
  if (inputs.balance < minBalance) {
    throw new CryptoError(`Balance ${inputs.balance} is below the minimum ${minBalance}`);
  }
}
