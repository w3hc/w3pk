/**
 * Zero-Knowledge Proof Types
 * General-purpose ZK proof system for privacy-preserving assertions
 */

export interface ZKProofConfig {
  /**
   * Enable/disable specific proof types
   */
  enabledProofs?: ProofType[];

  /**
   * Custom circuit paths (optional)
   */
  customCircuits?: Record<string, CircuitArtifacts>;
}

export type ProofType =
  | "membership" // Prove membership in a set without revealing identity
  | "threshold" // Prove value > threshold without revealing value
  | "range" // Prove value in range without revealing value
  | "equality" // Prove equality without revealing values
  | "ownership" // Prove ownership without revealing private key
  | "signature" // Prove signature validity without revealing signer
  | "nft"; // Prove NFT ownership without revealing which NFT or exact address

export interface CircuitArtifacts {
  wasmPath: string;
  zkeyPath: string;
  verificationKey: any;
}

export interface ProofInput {
  type: ProofType;
  privateInputs: Record<string, any>;
  publicInputs: Record<string, any>;
}

export interface ZKProof {
  type: ProofType;
  proof: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  };
  publicSignals: string[];
  timestamp: string;
}

export interface VerificationResult {
  valid: boolean;
  type: ProofType;
  publicSignals: Record<string, any>;
  timestamp: string;
}

/**
 * Membership Proof - Prove you're in a set without revealing which member
 */
export interface MembershipProofInput {
  // Private: your actual value/identity
  value: string;
  // Private: your position in the merkle tree
  pathIndices: number[];
  // Private: merkle proof siblings
  pathElements: string[];
  // Public: merkle root of the set
  root: string;
}

/**
 * Threshold Proof - Prove value exceeds threshold without revealing value
 */
export interface ThresholdProofInput {
  // Private: the actual value
  value: bigint;
  // Private: random blinding factor
  blinding: bigint;
  // Public: threshold to prove against
  threshold: bigint;
  // Public: commitment to the value
  commitment: string;
}

/**
 * Range Proof - Prove value is within range without revealing value
 */
export interface RangeProofInput {
  // Private: the actual value
  value: bigint;
  // Private: random blinding factor
  blinding: bigint;
  // Public: minimum value
  min: bigint;
  // Public: maximum value
  max: bigint;
  // Public: commitment to the value
  commitment: string;
}

/**
 * Ownership Proof - Prove you own an address without revealing private key
 */
export interface OwnershipProofInput {
  // Private: private key
  privateKey: string;
  // Private: random nonce
  nonce: bigint;
  // Public: Ethereum address
  address: string;
  // Public: challenge from verifier
  challenge: string;
}

/**
 * NFT Ownership Proof - Prove you own an NFT from a collection without revealing which one
 */
export interface NFTOwnershipProofInput {
  // Private: your address (as owner of the NFT)
  ownerAddress: string;
  // Private: your position in the holders merkle tree
  holderIndex: number;
  // Private: merkle proof path indices
  pathIndices: number[];
  // Private: merkle proof path elements
  pathElements: string[];
  // Public: merkle root of all NFT holders for this collection
  holdersRoot: string;
  // Public: NFT contract address
  contractAddress: string;
  // Public: minimum token balance to prove (default 1 for ownership)
  minBalance?: bigint;
}

/**
 * General proof builder interface
 */
export interface ProofBuilder {
  type: ProofType;
  build(inputs: any): Promise<ZKProof>;
  verify(proof: ZKProof): Promise<VerificationResult>;
}

/**
 * Circom circuit input format
 */
export interface CircomInputs {
  [key: string]: string | string[] | number | number[];
}
