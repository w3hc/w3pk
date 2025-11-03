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
          const hashResult = poseidon([currentLevel[i], currentLevel[i + 1]]);
          
          // Convert Uint8Array result to BigInt if needed
          const hash = hashResult instanceof Uint8Array 
            ? bufferToBigInt(hashResult) 
            : hashResult;
            
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

/**
 * Build NFT holders merkle tree
 * Creates a merkle tree from a list of NFT holder addresses for a specific contract
 */
export async function buildNFTHoldersMerkleTree(
  holderAddresses: string[],
  contractAddress: string
): Promise<{
  root: string;
  tree: string[][];
  holderLeaves: string[];
}> {
  try {
    // @ts-ignore - Optional dependency, may not be installed
    const circomlibjs = await import("circomlibjs");
    const poseidon = await circomlibjs.buildPoseidon();

    if (holderAddresses.length === 0) {
      throw new Error("Cannot build NFT holders tree from empty holder list");
    }

    // Create leaf hashes: Hash(holderAddress, contractAddress)
    // Convert hex addresses to BigInt (remove 0x prefix first)
    const contractHash = BigInt(contractAddress.startsWith('0x') ? contractAddress : '0x' + contractAddress);
    const holderLeaves = holderAddresses.map((address) => {
      const cleanAddress = address.startsWith('0x') ? address : '0x' + address;
      const addressHash = BigInt(cleanAddress);
      const hashResult = poseidon([addressHash, contractHash]);
      
      // Convert Uint8Array result to BigInt if needed
      if (hashResult instanceof Uint8Array) {
        return bufferToBigInt(hashResult).toString();
      }
      
      return hashResult.toString();
    });

    // Build merkle tree from the leaves
    const { root, tree } = await buildMerkleTree(holderLeaves);

    return {
      root,
      tree,
      holderLeaves,
    };
  } catch (error) {
    if (error instanceof Error && error.message.includes("Cannot resolve module")) {
      throw new CryptoError(
        "NFT holder merkle tree requires circomlibjs. Install with: npm install circomlibjs\n" +
        "For more info: https://github.com/w3hc/w3pk#zero-knowledge-proofs",
        error
      );
    }
    throw new CryptoError("Failed to build NFT holders merkle tree", error);
  }
}

/**
 * Generate NFT ownership proof inputs
 * Helper to prepare all inputs needed for NFT ownership proof
 */
export async function generateNFTOwnershipProofInputs(
  ownerAddress: string,
  contractAddress: string,
  allHolderAddresses: string[],
  minBalance: bigint = 1n
): Promise<{
  nftProofInput: {
    ownerAddress: string;
    holderIndex: number;
    pathIndices: number[];
    pathElements: string[];
    holdersRoot: string;
    contractAddress: string;
    minBalance: bigint;
  };
  holderLeaves: string[];
}> {
  // Find the owner's position in the holders list
  const holderIndex = allHolderAddresses.findIndex(
    (address) => address.toLowerCase() === ownerAddress.toLowerCase()
  );

  if (holderIndex === -1) {
    throw new CryptoError(
      `Owner address ${ownerAddress} not found in holders list for contract ${contractAddress}`
    );
  }

  // Build the NFT holders merkle tree
  const { root, tree, holderLeaves } = await buildNFTHoldersMerkleTree(
    allHolderAddresses,
    contractAddress
  );

  // Generate merkle proof for this owner
  const { pathIndices, pathElements } = generateMerkleProof(tree, holderIndex);

  return {
    nftProofInput: {
      ownerAddress,
      holderIndex,
      pathIndices,
      pathElements,
      holdersRoot: root,
      contractAddress,
      minBalance,
    },
    holderLeaves,
  };
}

/**
 * Validate NFT ownership proof inputs
 */
export function validateNFTOwnershipProofInputs(inputs: {
  ownerAddress: string;
  contractAddress: string;
  holderIndex: number;
  pathIndices: number[];
  pathElements: string[];
  holdersRoot: string;
  minBalance?: bigint;
}): void {
  if (!isValidAddress(inputs.ownerAddress)) {
    throw new CryptoError(`Invalid owner address: ${inputs.ownerAddress}`);
  }

  if (!isValidAddress(inputs.contractAddress)) {
    throw new CryptoError(`Invalid contract address: ${inputs.contractAddress}`);
  }

  if (inputs.holderIndex < 0 || !Number.isInteger(inputs.holderIndex)) {
    throw new CryptoError(`Invalid holder index: ${inputs.holderIndex}`);
  }

  if (inputs.pathIndices.length !== inputs.pathElements.length) {
    throw new CryptoError(
      `Path indices and elements length mismatch: ${inputs.pathIndices.length} vs ${inputs.pathElements.length}`
    );
  }

  if (inputs.pathIndices.length === 0) {
    throw new CryptoError("Empty merkle proof path");
  }

  if (!inputs.holdersRoot || inputs.holdersRoot.length === 0) {
    throw new CryptoError("Invalid holders root");
  }

  if (inputs.minBalance && inputs.minBalance < 1n) {
    throw new CryptoError("Minimum balance must be at least 1");
  }
}
