pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

/**
 * Membership Proof Circuit
 * Proves that a leaf exists in a merkle tree without revealing which leaf
 * 
 * Private inputs:
 *   - leaf: the actual leaf value (your identity/credential)
 *   - pathElements: siblings in the merkle tree path
 *   - pathIndices: binary path from leaf to root
 * 
 * Public inputs:
 *   - root: the merkle tree root (publicly known)
 * 
 * Output:
 *   - Proof that you know a leaf in the tree, without revealing which leaf
 */
template MembershipProof(levels) {
    // Private inputs
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    
    // Public inputs
    signal input root;
    
    // Output
    signal output nullifier; // Prevents double-spending
    
    // Hash the leaf to create a nullifier
    component leafHasher = Poseidon(1);
    leafHasher.inputs[0] <== leaf;
    nullifier <== leafHasher.out;
    
    // Merkle tree verification
    component merkleProof[levels];
    signal currentHash[levels + 1];
    signal left[levels];  // Pre-declare arrays outside the loop
    signal right[levels];
    
    currentHash[0] <== leaf;
    
    for (var i = 0; i < levels; i++) {
        merkleProof[i] = Poseidon(2);
        
        // Simple conditional logic to avoid non-quadratic constraints
        // pathIndices[i] is 0 or 1, so we can use it as a selector
        left[i] <== currentHash[i] + pathIndices[i] * (pathElements[i] - currentHash[i]);
        right[i] <== pathElements[i] + pathIndices[i] * (currentHash[i] - pathElements[i]);
        
        merkleProof[i].inputs[0] <== left[i];
        merkleProof[i].inputs[1] <== right[i];
        
        currentHash[i + 1] <== merkleProof[i].out;
    }
    
    // Verify that the computed root matches the public root
    root === currentHash[levels];
}

// Instantiate the circuit with 20 levels (supports up to 1M users)
component main = MembershipProof(20);