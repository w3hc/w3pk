/**
 * ZK Proof Generator
 * Generates zero-knowledge proofs using circom circuits
 */

import { CryptoError } from "../core/errors";
import { bufferToBigInt } from "./utils";
import type {
  ProofType,
  ZKProof,
  CircuitArtifacts,
  CircomInputs,
  MembershipProofInput,
  ThresholdProofInput,
  RangeProofInput,
  OwnershipProofInput,
  NFTOwnershipProofInput,
} from "./types";

export class ZKProofGenerator {
  private circuits: Map<ProofType, CircuitArtifacts> = new Map();
  private snarkjs: any;

  constructor() {
    this.loadSnarkJS();
  }

  private async loadSnarkJS() {
    try {
      // Dynamic import for optional dependency
      this.snarkjs = await import("snarkjs");
    } catch (error) {
      // Don't throw immediately - only throw when actually trying to use it
      this.snarkjs = null;
    }
  }

  /**
   * Register a circuit for a specific proof type
   */
  registerCircuit(type: ProofType, artifacts: CircuitArtifacts): void {
    this.circuits.set(type, artifacts);
  }

  /**
   * Generate membership proof - prove you're in a merkle tree set
   */
  async generateMembershipProof(input: MembershipProofInput): Promise<ZKProof> {
    const circuit = this.circuits.get("membership");
    if (!circuit) {
      throw new CryptoError("Membership circuit not registered");
    }

    const circuitInputs: CircomInputs = {
      leaf: input.value,
      pathIndices: input.pathIndices,
      pathElements: input.pathElements,
      root: input.root,
    };

    return this.generateProof("membership", circuit, circuitInputs);
  }

  /**
   * Generate threshold proof - prove value > threshold
   */
  async generateThresholdProof(input: ThresholdProofInput): Promise<ZKProof> {
    const circuit = this.circuits.get("threshold");
    if (!circuit) {
      throw new CryptoError("Threshold circuit not registered");
    }

    const circuitInputs: CircomInputs = {
      value: input.value.toString(),
      blinding: input.blinding.toString(),
      threshold: input.threshold.toString(),
      commitment: input.commitment,
    };

    return this.generateProof("threshold", circuit, circuitInputs);
  }

  /**
   * Generate range proof - prove min <= value <= max
   */
  async generateRangeProof(input: RangeProofInput): Promise<ZKProof> {
    const circuit = this.circuits.get("range");
    if (!circuit) {
      throw new CryptoError("Range circuit not registered");
    }

    const circuitInputs: CircomInputs = {
      value: input.value.toString(),
      blinding: input.blinding.toString(),
      min: input.min.toString(),
      max: input.max.toString(),
      commitment: input.commitment,
    };

    return this.generateProof("range", circuit, circuitInputs);
  }

  /**
   * Generate ownership proof - prove you own an address
   */
  async generateOwnershipProof(input: OwnershipProofInput): Promise<ZKProof> {
    const circuit = this.circuits.get("ownership");
    if (!circuit) {
      throw new CryptoError("Ownership circuit not registered");
    }

    const circuitInputs: CircomInputs = {
      privateKey: input.privateKey,
      nonce: input.nonce.toString(),
      address: input.address,
      challenge: input.challenge,
    };

    return this.generateProof("ownership", circuit, circuitInputs);
  }

  /**
   * Generate NFT ownership proof - prove you own an NFT from a collection
   */
  async generateNFTOwnershipProof(input: NFTOwnershipProofInput): Promise<ZKProof> {
    const circuit = this.circuits.get("nft");
    if (!circuit) {
      throw new CryptoError("NFT ownership circuit not registered");
    }

    // Hash the owner address and contract address for privacy
    const poseidon = await this.getPoseidonHash();
    const cleanOwnerAddress = input.ownerAddress.startsWith('0x') ? input.ownerAddress : '0x' + input.ownerAddress;
    const cleanContractAddress = input.contractAddress.startsWith('0x') ? input.contractAddress : '0x' + input.contractAddress;
    
    const ownerHashResult = poseidon([BigInt(cleanOwnerAddress)]);
    const contractHashResult = poseidon([BigInt(cleanContractAddress)]);
    
    // Convert Uint8Array results to BigInt if needed
    const ownerAddressHash = ownerHashResult instanceof Uint8Array 
      ? bufferToBigInt(ownerHashResult) 
      : ownerHashResult;
    const contractAddressHash = contractHashResult instanceof Uint8Array 
      ? bufferToBigInt(contractHashResult) 
      : contractHashResult;

    const circuitInputs: CircomInputs = {
      ownerAddress: ownerAddressHash.toString(),
      pathElements: input.pathElements,
      pathIndices: input.pathIndices,
      root: input.holdersRoot,
      contractAddress: contractAddressHash.toString(),
      minBalance: (input.minBalance || 1n).toString(),
    };

    return this.generateProof("nft", circuit, circuitInputs);
  }

  /**
   * Core proof generation logic
   */
  private async generateProof(
    type: ProofType,
    circuit: CircuitArtifacts,
    inputs: CircomInputs
  ): Promise<ZKProof> {
    try {
      if (!this.snarkjs) {
        await this.loadSnarkJS();
        if (!this.snarkjs) {
          throw new CryptoError(
            "ZK proofs require snarkjs. Install with: npm install snarkjs\n" +
            "For more info: https://github.com/w3hc/w3pk#zero-knowledge-proofs"
          );
        }
      }

      // Calculate witness
      const { proof, publicSignals } = await this.snarkjs.groth16.fullProve(
        inputs,
        circuit.wasmPath,
        circuit.zkeyPath
      );

      return {
        type,
        proof: {
          pi_a: proof.pi_a.map((x: any) => x.toString()),
          pi_b: proof.pi_b.map((arr: any[]) =>
            arr.map((x: any) => x.toString())
          ),
          pi_c: proof.pi_c.map((x: any) => x.toString()),
          protocol: proof.protocol || "groth16",
          curve: proof.curve || "bn128",
        },
        publicSignals: publicSignals.map((x: any) => x.toString()),
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      throw new CryptoError(
        `Failed to generate ${type} proof: ${
          error instanceof Error ? error.message : "Unknown error"
        }`,
        error
      );
    }
  }

  /**
   * Create a Pedersen commitment: H(value, blinding)
   */
  async createCommitment(value: bigint, blinding: bigint): Promise<string> {
    try {
      // Use Poseidon hash for commitment (no snarkjs utils needed)
      const poseidon = await this.getPoseidonHash();
      const commitment = poseidon([value, blinding]);

      return commitment.toString();
    } catch (error) {
      throw new CryptoError("Failed to create commitment", error);
    }
  }

  /**
   * Get Poseidon hash function
   */
  private async getPoseidonHash(): Promise<any> {
    try {
      // Dynamic import with type assertion for optional dependency
      const circomlibjs = (await import("circomlibjs")) as any;
      return await circomlibjs.buildPoseidon();
    } catch (error) {
      throw new CryptoError(
        "ZK proofs require circomlibjs. Install with: npm install circomlibjs\n" +
        "For more info: https://github.com/w3hc/w3pk#zero-knowledge-proofs",
        error
      );
    }
  }

  /**
   * Compute merkle root from leaf and proof
   */
  async computeMerkleRoot(
    leaf: string,
    pathIndices: number[],
    pathElements: string[]
  ): Promise<string> {
    try {
      const poseidon = await this.getPoseidonHash();
      let current = BigInt(leaf);

      for (let i = 0; i < pathElements.length; i++) {
        const sibling = BigInt(pathElements[i]);
        const index = pathIndices[i];

        if (index === 0) {
          current = poseidon([current, sibling]);
        } else {
          current = poseidon([sibling, current]);
        }
      }

      return current.toString();
    } catch (error) {
      throw new CryptoError("Failed to compute merkle root", error);
    }
  }
}
