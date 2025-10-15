pragma circom 2.0.0;

include "../../../node_modules/circomlib/circuits/poseidon.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";

/**
 * Range Proof Circuit
 * Proves that a hidden value is within a range without revealing the value
 * 
 * Private inputs:
 *   - value: the actual value
 *   - blinding: random blinding factor for commitment
 * 
 * Public inputs:
 *   - min: minimum value (inclusive)
 *   - max: maximum value (inclusive)
 *   - commitment: Poseidon(value, blinding)
 * 
 * Proves: min <= value <= max
 */
template RangeProof() {
    // Private inputs
    signal input value;
    signal input blinding;
    
    // Public inputs
    signal input min;
    signal input max;
    signal input commitment;

    // 1. Verify commitment
    component hasher = Poseidon(2);
    hasher.inputs[0] <== value;
    hasher.inputs[1] <== blinding;
    commitment === hasher.out;

    // 2. Prove value >= min
    component greaterThanMin = GreaterEqThan(252);
    greaterThanMin.in[0] <== value;
    greaterThanMin.in[1] <== min;
    greaterThanMin.out === 1;

    // 3. Prove value <= max
    component lessThanMax = LessEqThan(252);
    lessThanMax.in[0] <== value;
    lessThanMax.in[1] <== max;
    lessThanMax.out === 1;
}

component main {public [min, max, commitment]} = RangeProof();