/**
 * ZK Proof Verifier
 * Verifies zero-knowledge proofs using verification keys
 */

import { CryptoError } from "../core/errors";
import type {
  ProofType,
  ZKProof,
  VerificationResult,
  CircuitArtifacts,
} from "./types";

export class ZKProofVerifier {
  private circuits: Map<ProofType, CircuitArtifacts> = new Map();
  private snarkjs: any;

  constructor() {
    this.loadSnarkJS();
  }

  private async loadSnarkJS() {
    try {
      this.snarkjs = await import("snarkjs");
    } catch (error) {
      // Don't throw immediately - only throw when actually trying to use it
      this.snarkjs = null;
    }
  }

  /**
   * Register a circuit's verification key
   */
  registerCircuit(type: ProofType, artifacts: CircuitArtifacts): void {
    this.circuits.set(type, artifacts);
  }

  /**
   * Verify any ZK proof
   */
  async verifyProof(proof: ZKProof): Promise<VerificationResult> {
    try {
      const circuit = this.circuits.get(proof.type);
      if (!circuit) {
        throw new CryptoError(`Circuit not registered for type: ${proof.type}`);
      }

      if (!this.snarkjs) {
        await this.loadSnarkJS();
        if (!this.snarkjs) {
          throw new CryptoError(
            "ZK proof verification requires snarkjs. Install with: npm install snarkjs\n" +
            "For more info: https://github.com/w3hc/w3pk#zero-knowledge-proofs"
          );
        }
      }

      // Verify the proof
      const isValid = await this.snarkjs.groth16.verify(
        circuit.verificationKey,
        proof.publicSignals,
        proof.proof
      );

      return {
        valid: isValid,
        type: proof.type,
        publicSignals: this.parsePublicSignals(proof.type, proof.publicSignals),
        timestamp: proof.timestamp,
      };
    } catch (error) {
      throw new CryptoError(
        `Proof verification failed: ${
          error instanceof Error ? error.message : "Unknown error"
        }`,
        error
      );
    }
  }

  /**
   * Batch verify multiple proofs efficiently
   */
  async verifyBatch(proofs: ZKProof[]): Promise<VerificationResult[]> {
    const results = await Promise.all(
      proofs.map((proof) => this.verifyProof(proof))
    );
    return results;
  }

  /**
   * Verify membership proof against the expected root and scope (default 0).
   * Store `publicSignals[0]`, the nullifier, to refuse a second proof from
   * the same leaf in the same scope.
   */
  async verifyMembershipProof(
    proof: ZKProof,
    expectedRoot: string,
    expectedScope: bigint | string = 0n
  ): Promise<boolean> {
    if (proof.type !== "membership") {
      throw new CryptoError("Invalid proof type for membership verification");
    }

    const result = await this.verifyProof(proof);
    const [, root, scope] = proof.publicSignals;

    return (
      result.valid &&
      root === expectedRoot &&
      scope === BigInt(expectedScope).toString()
    );
  }

  /**
   * Verify threshold proof
   */
  async verifyThresholdProof(
    proof: ZKProof,
    expectedCommitment: string,
    expectedThreshold: bigint
  ): Promise<boolean> {
    if (proof.type !== "threshold") {
      throw new CryptoError("Invalid proof type for threshold verification");
    }

    const result = await this.verifyProof(proof);

    const [publicThreshold, publicCommitment] = proof.publicSignals;

    return (
      result.valid &&
      publicCommitment === expectedCommitment &&
      publicThreshold === expectedThreshold.toString()
    );
  }

  /**
   * Verify range proof
   */
  async verifyRangeProof(
    proof: ZKProof,
    expectedCommitment: string,
    expectedMin: bigint,
    expectedMax: bigint
  ): Promise<boolean> {
    if (proof.type !== "range") {
      throw new CryptoError("Invalid proof type for range verification");
    }

    const result = await this.verifyProof(proof);

    const [publicMin, publicMax, publicCommitment] = proof.publicSignals;

    return (
      result.valid &&
      publicCommitment === expectedCommitment &&
      publicMin === expectedMin.toString() &&
      publicMax === expectedMax.toString()
    );
  }

  /**
   * Verify ownership proof
   */
  async verifyOwnershipProof(
    proof: ZKProof,
    expectedAddress: string,
    expectedChallenge: string
  ): Promise<boolean> {
    if (proof.type !== "ownership") {
      throw new CryptoError("Invalid proof type for ownership verification");
    }

    const result = await this.verifyProof(proof);

    const publicAddress = proof.publicSignals[0];
    const publicChallenge = proof.publicSignals[1];

    return (
      result.valid &&
      publicAddress.toLowerCase() === expectedAddress.toLowerCase() &&
      publicChallenge === expectedChallenge
    );
  }

  /**
   * Verify NFT ownership proof against the expected contract, holders root
   * and scope. Store `publicSignals[0]`, the nullifier, to refuse a second
   * proof from the same holder in the same scope.
   */
  async verifyNFTOwnershipProof(
    proof: ZKProof,
    expectedContract: string,
    expectedHoldersRoot: string,
    expectedMinBalance: bigint,
    expectedScope: bigint | string
  ): Promise<boolean> {
    if (proof.type !== "nft") {
      throw new CryptoError("Invalid proof type for NFT ownership verification");
    }

    const result = await this.verifyProof(proof);
    const [, holdersRoot, contractAddress, minBalance, scope] = proof.publicSignals;

    return (
      result.valid &&
      holdersRoot === expectedHoldersRoot &&
      contractAddress === BigInt(expectedContract).toString() &&
      scope === BigInt(expectedScope).toString() &&
      BigInt(minBalance) >= expectedMinBalance
    );
  }

  /**
   * Parse public signals based on proof type
   */
  private parsePublicSignals(
    type: ProofType,
    signals: string[]
  ): Record<string, string> {
    switch (type) {
      case "membership":
        return {
          nullifier: signals[0],
          root: signals[1],
          scope: signals[2],
        };

      case "threshold":
        return {
          threshold: signals[0],
          commitment: signals[1],
        };

      case "range":
        return {
          min: signals[0],
          max: signals[1],
          commitment: signals[2],
        };

      case "ownership":
        return {
          address: signals[0],
          challenge: signals[1],
        };

      case "nft":
        return {
          nullifier: signals[0],
          holdersRoot: signals[1],
          contractAddress: signals[2],
          minBalance: signals[3],
          scope: signals[4],
        };

      default:
        return signals.reduce((acc, signal, idx) => {
          acc[`signal_${idx}`] = signal;
          return acc;
        }, {} as Record<string, string>);
    }
  }

  /**
   * Check if proof is expired (optional time validation)
   */
  isProofExpired(proof: ZKProof, maxAgeMs: number = 3600000): boolean {
    const age = Date.now() - new Date(proof.timestamp).getTime();
    return age > maxAgeMs;
  }
}
