pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

/**
 * Simplified Ownership Proof Circuit
 * Proves knowledge of a secret that corresponds to a public commitment
 * This is a simplified version - for full Ethereum address ownership,
 * you would need secp256k1/ECDSA circuits not available in circomlib
 * 
 * Private inputs:
 *   - secret: private secret value (like a private key hash)
 *   - nonce: prevents rainbow table attacks
 * 
 * Public inputs:
 *   - publicCommitment: hash of the secret (like a public key hash)
 * 
 * Output:
 *   - Proof that you know the secret corresponding to the commitment
 */
template OwnershipProof() {
    // Private inputs
    signal input secret;
    signal input nonce;
    
    // Public inputs  
    signal input publicCommitment;
    
    // Output - nullifier to prevent double-spending
    signal output nullifier;
    
    // Create commitment from secret and nonce
    component hasher = Poseidon(2);
    hasher.inputs[0] <== secret;
    hasher.inputs[1] <== nonce;
    
    // Verify the commitment matches
    publicCommitment === hasher.out;
    
    // Create nullifier from secret (different from commitment)
    component nullifierHasher = Poseidon(1);
    nullifierHasher.inputs[0] <== secret;
    nullifier <== nullifierHasher.out;
}

// Instantiate the circuit
component main = OwnershipProof();