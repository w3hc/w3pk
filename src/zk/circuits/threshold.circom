pragma circom 2.0.0;

include "../../../node_modules/circomlib/circuits/poseidon.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";

/**
 * Threshold Proof Circuit
 * Proves that a hidden value exceeds a threshold without revealing the value
 * 
 * Private inputs:
 *   - value: the actual value (e.g., balance, age, score)
 *   - blinding: random blinding factor for commitment
 * 
 * Public inputs:
 *   - threshold: the minimum value to prove against
 *   - commitment: Poseidon(value, blinding) - commitment to the value
 * 
 * Proves: value >= threshold
 */
template ThresholdProof() {
    // Private inputs
    signal input value;
    signal input blinding;
    
    // Public inputs
    signal input threshold;
    signal input commitment;

    // 1. Verify commitment
    component hasher = Poseidon(2);
    hasher.inputs[0] <== value;
    hasher.inputs[1] <== blinding;
    commitment === hasher.out;

    // 2. Prove value >= threshold
    component greaterThan = GreaterEqThan(252);
    greaterThan.in[0] <== value;
    greaterThan.in[1] <== threshold;
    greaterThan.out === 1;
}

component main {public [threshold, commitment]} = ThresholdProof();