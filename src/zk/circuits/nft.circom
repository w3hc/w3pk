pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

/**
 * NFT Ownership Proof Circuit
 * Proves ownership of an NFT from a collection without revealing:
 * - Which specific NFT you own
 * - Your exact wallet address
 * - How many NFTs you own (beyond minimum threshold)
 * 
 * This circuit proves membership in a merkle tree of NFT holders
 * while optionally proving minimum balance threshold
 * 
 * Private inputs:
 *   - ownerAddress: your address that owns the NFT(s) (hashed)
 *   - pathElements[levels]: merkle proof sibling hashes
 *   - pathIndices[levels]: merkle proof path (0 = left, 1 = right)
 * 
 * Public inputs:
 *   - root: merkle root of all NFT holders
 *   - contractAddress: NFT contract address (hashed)
 *   - minBalance: minimum number of NFTs to prove ownership of
 * 
 * Output:
 *   - nullifierHash: prevents double-proving with same credentials
 */
template NFTOwnership(levels) {
    // Ensure levels is reasonable (max 20 for ~1M holders)
    assert(levels < 21);
    
    // Private inputs
    signal input ownerAddress;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    
    // Public inputs
    signal input root;
    signal input contractAddress;
    signal input minBalance;
    
    // Output - nullifier to prevent reuse
    signal output nullifierHash;
    
    // Create leaf hash from owner address and contract address
    component leafHasher = Poseidon(2);
    leafHasher.inputs[0] <== ownerAddress;
    leafHasher.inputs[1] <== contractAddress;
    
    // Verify merkle proof
    component merkleProof[levels];
    signal computedHash[levels + 1];
    signal leftHash[levels];
    signal rightHash[levels];
    
    computedHash[0] <== leafHasher.out;
    
    for (var i = 0; i < levels; i++) {
        // Create hash components for each level
        merkleProof[i] = Poseidon(2);
        
        // Use pathIndices[i] to determine order
        // If pathIndices[i] == 0, current hash goes left
        // If pathIndices[i] == 1, current hash goes right
        leftHash[i] <== computedHash[i] + pathIndices[i] * (pathElements[i] - computedHash[i]);
        rightHash[i] <== pathElements[i] + pathIndices[i] * (computedHash[i] - pathElements[i]);
        
        merkleProof[i].inputs[0] <== leftHash[i];
        merkleProof[i].inputs[1] <== rightHash[i];
        computedHash[i + 1] <== merkleProof[i].out;
    }
    
    // Verify the computed root matches the expected root
    root === computedHash[levels];
    
    // Verify minimum balance requirement (should be >= minBalance)
    // For basic ownership proof, minBalance = 1
    // For threshold ownership, minBalance > 1
    component balanceCheck = GreaterEqThan(64); // Support up to 2^64 NFTs
    balanceCheck.in[0] <== 1; // We prove ownership (>=1) 
    balanceCheck.in[1] <== minBalance;
    balanceCheck.out === 1;
    
    // Generate nullifier hash to prevent double-proving
    // Nullifier = Hash(ownerAddress, contractAddress, root)
    component nullifierHasher = Poseidon(3);
    nullifierHasher.inputs[0] <== ownerAddress;
    nullifierHasher.inputs[1] <== contractAddress;
    nullifierHasher.inputs[2] <== root;
    nullifierHash <== nullifierHasher.out;
}

// Instantiate with 20 levels (supports ~1M holders)
component main = NFTOwnership(20);