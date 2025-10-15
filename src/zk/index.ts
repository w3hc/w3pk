/**
 * Zero-Knowledge Proof Module for w3pk SDK
 * Enables privacy-preserving proofs
 */

import { Web3PasskeyError } from "../core/errors";
import { ZKProofGenerator } from "./proof-generator";
import { ZKProofVerifier } from "./proof-verifier";
import type {
  ZKProofConfig,
  ProofType,
  ZKProof,
  VerificationResult,
  MembershipProofInput,
  ThresholdProofInput,
  RangeProofInput,
  OwnershipProofInput,
  CircuitArtifacts,
} from "./types";

export class ZKProofModule {
  private generator: ZKProofGenerator;
  private verifier: ZKProofVerifier;
  private config: ZKProofConfig;

  constructor(config: ZKProofConfig = {}) {
    this.config = config;
    this.generator = new ZKProofGenerator();
    this.verifier = new ZKProofVerifier();
    this.initializeCircuits();
  }

  private async initializeCircuits() {
    // Circuits can be registered dynamically as needed
    // In production, these would point to actual compiled circuit artifacts
  }

  // ========================================
  // Proof Generation
  // ========================================

  /**
   * Generate membership proof - prove you're in a set without revealing identity
   * Use case: Prove you're a verified user without revealing which one
   */
  async proveMembership(input: MembershipProofInput): Promise<ZKProof> {
    try {
      this.assertProofEnabled("membership");
      return await this.generator.generateMembershipProof(input);
    } catch (error) {
      throw new Web3PasskeyError(
        "Failed to generate membership proof",
        "ZK_MEMBERSHIP_ERROR",
        error
      );
    }
  }

  /**
   * Generate threshold proof - prove value exceeds threshold
   * Use case: Prove balance > $1000 without revealing actual balance
   */
  async proveThreshold(input: ThresholdProofInput): Promise<ZKProof> {
    try {
      this.assertProofEnabled("threshold");
      return await this.generator.generateThresholdProof(input);
    } catch (error) {
      throw new Web3PasskeyError(
        "Failed to generate threshold proof",
        "ZK_THRESHOLD_ERROR",
        error
      );
    }
  }

  /**
   * Generate range proof - prove value is within range
   * Use case: Prove age between 18-65 without revealing exact age
   */
  async proveRange(input: RangeProofInput): Promise<ZKProof> {
    try {
      this.assertProofEnabled("range");
      return await this.generator.generateRangeProof(input);
    } catch (error) {
      throw new Web3PasskeyError(
        "Failed to generate range proof",
        "ZK_RANGE_ERROR",
        error
      );
    }
  }

  /**
   * Generate ownership proof - prove you own an address
   * Use case: Prove ownership without revealing private key
   */
  async proveOwnership(input: OwnershipProofInput): Promise<ZKProof> {
    try {
      this.assertProofEnabled("ownership");
      return await this.generator.generateOwnershipProof(input);
    } catch (error) {
      throw new Web3PasskeyError(
        "Failed to generate ownership proof",
        "ZK_OWNERSHIP_ERROR",
        error
      );
    }
  }

  // ========================================
  // Proof Verification
  // ========================================

  /**
   * Verify any ZK proof
   */
  async verify(proof: ZKProof): Promise<VerificationResult> {
    try {
      return await this.verifier.verifyProof(proof);
    } catch (error) {
      throw new Web3PasskeyError(
        "Failed to verify proof",
        "ZK_VERIFICATION_ERROR",
        error
      );
    }
  }

  /**
   * Batch verify multiple proofs
   */
  async verifyBatch(proofs: ZKProof[]): Promise<VerificationResult[]> {
    try {
      return await this.verifier.verifyBatch(proofs);
    } catch (error) {
      throw new Web3PasskeyError(
        "Failed to verify proofs",
        "ZK_BATCH_VERIFICATION_ERROR",
        error
      );
    }
  }

  /**
   * Verify membership proof with expected root
   */
  async verifyMembership(
    proof: ZKProof,
    expectedRoot: string
  ): Promise<boolean> {
    try {
      return await this.verifier.verifyMembershipProof(proof, expectedRoot);
    } catch (error) {
      throw new Web3PasskeyError(
        "Failed to verify membership proof",
        "ZK_MEMBERSHIP_VERIFICATION_ERROR",
        error
      );
    }
  }

  /**
   * Verify threshold proof
   */
  async verifyThreshold(
    proof: ZKProof,
    expectedCommitment: string,
    expectedThreshold: bigint
  ): Promise<boolean> {
    try {
      return await this.verifier.verifyThresholdProof(
        proof,
        expectedCommitment,
        expectedThreshold
      );
    } catch (error) {
      throw new Web3PasskeyError(
        "Failed to verify threshold proof",
        "ZK_THRESHOLD_VERIFICATION_ERROR",
        error
      );
    }
  }

  /**
   * Verify range proof
   */
  async verifyRange(
    proof: ZKProof,
    expectedCommitment: string,
    expectedMin: bigint,
    expectedMax: bigint
  ): Promise<boolean> {
    try {
      return await this.verifier.verifyRangeProof(
        proof,
        expectedCommitment,
        expectedMin,
        expectedMax
      );
    } catch (error) {
      throw new Web3PasskeyError(
        "Failed to verify range proof",
        "ZK_RANGE_VERIFICATION_ERROR",
        error
      );
    }
  }

  /**
   * Verify ownership proof
   */
  async verifyOwnership(
    proof: ZKProof,
    expectedAddress: string,
    expectedChallenge: string
  ): Promise<boolean> {
    try {
      return await this.verifier.verifyOwnershipProof(
        proof,
        expectedAddress,
        expectedChallenge
      );
    } catch (error) {
      throw new Web3PasskeyError(
        "Failed to verify ownership proof",
        "ZK_OWNERSHIP_VERIFICATION_ERROR",
        error
      );
    }
  }

  // ========================================
  // Utility Methods
  // ========================================

  /**
   * Create a Pedersen commitment for hiding values
   */
  async createCommitment(value: bigint, blinding: bigint): Promise<string> {
    try {
      return await this.generator.createCommitment(value, blinding);
    } catch (error) {
      throw new Web3PasskeyError(
        "Failed to create commitment",
        "ZK_COMMITMENT_ERROR",
        error
      );
    }
  }

  /**
   * Compute merkle root for membership proofs
   */
  async computeMerkleRoot(
    leaf: string,
    pathIndices: number[],
    pathElements: string[]
  ): Promise<string> {
    try {
      return await this.generator.computeMerkleRoot(
        leaf,
        pathIndices,
        pathElements
      );
    } catch (error) {
      throw new Web3PasskeyError(
        "Failed to compute merkle root",
        "ZK_MERKLE_ERROR",
        error
      );
    }
  }

  /**
   * Register a custom circuit
   */
  registerCircuit(type: ProofType, artifacts: CircuitArtifacts): void {
    this.generator.registerCircuit(type, artifacts);
    this.verifier.registerCircuit(type, artifacts);
  }

  /**
   * Check if proof type is enabled
   */
  private assertProofEnabled(type: ProofType): void {
    if (
      this.config.enabledProofs &&
      !this.config.enabledProofs.includes(type)
    ) {
      throw new Web3PasskeyError(
        `Proof type '${type}' is not enabled`,
        "ZK_PROOF_DISABLED"
      );
    }
  }

  /**
   * Check if ZK proofs are available
   */
  get isAvailable(): boolean {
    return true;
  }
}

// Export types
export type {
  ZKProofConfig,
  ProofType,
  ZKProof,
  VerificationResult,
  MembershipProofInput,
  ThresholdProofInput,
  RangeProofInput,
  OwnershipProofInput,
  CircuitArtifacts,
};
