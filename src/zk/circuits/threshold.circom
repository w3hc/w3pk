pragma circom 2.0.0;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";

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
 * Proves: value >= threshold, both below 2^128
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

    // 2. Both under 2^128, or GreaterEqThan wraps around the field
    component valueBits = Num2Bits(128);
    valueBits.in <== value;
    component thresholdBits = Num2Bits(128);
    thresholdBits.in <== threshold;

    // 3. Prove value >= threshold
    component greaterThan = GreaterEqThan(128);
    greaterThan.in[0] <== value;
    greaterThan.in[1] <== threshold;
    greaterThan.out === 1;
}

component main {public [threshold, commitment]} = ThresholdProof();