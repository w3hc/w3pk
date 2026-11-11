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
 *   - scope: external scope the nullifier is bound to
 *
 * Output:
 *   - nullifier: Poseidon(scope, leaf), one per leaf and scope
 */
template MembershipProof(levels) {
    // Private inputs
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    
    // Public inputs
    signal input root;
    signal input scope;

    signal output nullifier;

    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== scope;
    nullifierHasher.inputs[1] <== leaf;
    nullifier <== nullifierHasher.out;
    
    // Merkle tree verification
    component merkleProof[levels];
    signal currentHash[levels + 1];
    signal left[levels];  // Pre-declare arrays outside the loop
    signal right[levels];
    
    currentHash[0] <== leaf;
    
    for (var i = 0; i < levels; i++) {
        merkleProof[i] = Poseidon(2);
        
        pathIndices[i] * (pathIndices[i] - 1) === 0;

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
component main {public [root, scope]} = MembershipProof(20);