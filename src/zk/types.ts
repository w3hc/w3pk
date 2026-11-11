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

  /**
   * 32-byte private key of the NFT holder identity for a contract.
   * Web3Passkey sets it from the wallet in the session.
   */
  nftHolderKey?: (contractAddress: string) => Promise<Uint8Array>;
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
  verificationKey: unknown;
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
  publicSignals: Record<string, string>;
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
  // Public: external scope; one nullifier per leaf and scope (default: root)
  scope?: bigint | string;
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
 * NFT Ownership Proof - Prove a holder identity in a holders tree holds at
 * least `minBalance` tokens, without revealing which holder. The identity's
 * secret is never an input: the module derives it for `contractAddress`.
 */
export interface NFTOwnershipProofInput {
  // Private: the balance recorded in your leaf
  balance: bigint;
  // Private: merkle proof path indices (20 levels)
  pathIndices: number[];
  // Private: merkle proof path elements (20 levels)
  pathElements: string[];
  // Public: merkle root of the holders tree
  holdersRoot: string;
  // Public: NFT contract address
  contractAddress: string;
  // Public: minimum balance to prove (default 1)
  minBalance?: bigint;
  // Public: external scope; one nullifier per identity and scope
  scope: bigint | string;
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
