/**
 * ZK Proof Verifier
 * Verifies zero-knowledge proofs using verification keys
 */

import { CryptoError } from "../core/errors";
import { bufferToBigInt } from "./utils";
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
   * Verify membership proof
   */
  async verifyMembershipProof(
    proof: ZKProof,
    expectedRoot: string
  ): Promise<boolean> {
    if (proof.type !== "membership") {
      throw new CryptoError("Invalid proof type for membership verification");
    }

    const result = await this.verifyProof(proof);

    // Check that the public root matches expected
    const publicRoot = proof.publicSignals[0];
    return result.valid && publicRoot === expectedRoot;
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

    // Check public inputs match
    const publicCommitment = proof.publicSignals[0];
    const publicThreshold = BigInt(proof.publicSignals[1]);

    return (
      result.valid &&
      publicCommitment === expectedCommitment &&
      publicThreshold === expectedThreshold
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

    const publicCommitment = proof.publicSignals[0];
    const publicMin = BigInt(proof.publicSignals[1]);
    const publicMax = BigInt(proof.publicSignals[2]);

    return (
      result.valid &&
      publicCommitment === expectedCommitment &&
      publicMin === expectedMin &&
      publicMax === expectedMax
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
   * Verify NFT ownership proof with expected contract and holders root
   */
  async verifyNFTOwnershipProof(
    proof: ZKProof,
    expectedContract: string,
    expectedHoldersRoot: string,
    expectedMinBalance: bigint = 1n
  ): Promise<boolean> {
    if (proof.type !== "nft") {
      throw new CryptoError("Invalid proof type for NFT ownership verification");
    }

    const result = await this.verifyProof(proof);
    const holdersRoot = proof.publicSignals[0];
    const contractAddress = proof.publicSignals[1];
    const minBalance = BigInt(proof.publicSignals[2]);

    // Hash the expected contract address for comparison
    try {
      const circomlibjs = await import("circomlibjs");
      const poseidon = await circomlibjs.buildPoseidon();
      const cleanContract = expectedContract.startsWith('0x') ? expectedContract : '0x' + expectedContract;
      const hashResult = poseidon([BigInt(cleanContract)]);
      
      // Convert Uint8Array result to BigInt if needed
      const expectedContractHash = hashResult instanceof Uint8Array 
        ? bufferToBigInt(hashResult) 
        : hashResult;

      return (
        result.valid &&
        holdersRoot === expectedHoldersRoot &&
        contractAddress === expectedContractHash.toString() &&
        minBalance >= expectedMinBalance
      );
    } catch (error) {
      throw new CryptoError(
        "ZK proof verification requires circomlibjs. Install with: npm install circomlibjs\n" +
        "For more info: https://github.com/w3hc/w3pk#zero-knowledge-proofs",
        error
      );
    }
  }

  /**
   * Parse public signals based on proof type
   */
  private parsePublicSignals(
    type: ProofType,
    signals: string[]
  ): Record<string, any> {
    switch (type) {
      case "membership":
        return { root: signals[0] };

      case "threshold":
        return {
          commitment: signals[0],
          threshold: signals[1],
        };

      case "range":
        return {
          commitment: signals[0],
          min: signals[1],
          max: signals[2],
        };

      case "ownership":
        return {
          address: signals[0],
          challenge: signals[1],
        };

      case "nft":
        return {
          holdersRoot: signals[0],
          contractAddress: signals[1],
          minBalance: signals[2],
          nullifierHash: signals[3],
        };

      default:
        return signals.reduce((acc, signal, idx) => {
          acc[`signal_${idx}`] = signal;
          return acc;
        }, {} as Record<string, any>);
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
